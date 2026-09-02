// Sealing one message to many recipients — the channel case.
//
// ─────────────────────────────────────────────────────────────────────────────
// THE BODY IS ENCRYPTED ONCE, UNDER A FRESH CONTENT KEY, AND ONLY THAT KEY IS
// WRAPPED PER RECIPIENT.
//
// The obvious alternative — seal the plaintext separately to each recipient —
// is wrong for a reason that is not about storage. N independent ciphertexts of
// the same plaintext is a different construction with a larger surface, and it
// makes "everyone got the same message" unverifiable: nothing ties the copies
// together, so a sender could hand different members different text under one
// message id. ONE CIPHERTEXT MEANS ONE MESSAGE BY CONSTRUCTION.
//
// It also matches the shape the database already has. Migration 7 split
// DELIVERY per recipient and left CONTENT single, and that is the same
// distinction one layer down: one row of content, N facts about who gets it.
// ─────────────────────────────────────────────────────────────────────────────
//
// ⚠️ WHAT THIS DOES NOT HIDE, stated so it is a decision rather than a
// discovery: THE RECIPIENT LIST TRAVELS IN THE CLEAR. Anyone holding the
// envelope learns who else can open it.
//
// For a channel that is not new information — the server already fans out
// per-recipient delivery rows from membership it must know in order to route at
// all, and members already know the membership. It WOULD be new information if
// this were reused for an ad-hoc recipient set that the server does not
// otherwise learn, and that is the case to think again about rather than assume
// covered.

import { bufferToBase64, base64ToBuffer } from './keys';
import { deriveShared, deriveContentKey } from './sealing';
import { SealedMessageError } from '../types/errors';
import { ValidationError } from '../types/errors';

const GROUP_SEAL_VERSION = 1;
const IV_LENGTH = 12;
const CONTENT_KEY_BYTES = 32;

export interface GroupRecipient {
  /** Entity id, so a reader can find its own wrapped key without trial decryption. */
  entity: string;
  /** Base64 raw X25519 public key. */
  publicKey: string;
}

export interface WrappedKey {
  entity: string;
  /** Ephemeral X25519 public key for THIS recipient, base64. */
  ephemeralPublicKey: string;
  /** Nonce for the key-wrapping AES-GCM, base64. */
  iv: string;
  /** The content key, sealed to this recipient. Base64. */
  wrappedKey: string;
}

export interface SealedGroupEnvelope {
  version: number;
  /** Nonce for the BODY, base64. One body, one nonce. */
  iv: string;
  /** The message body under the content key, base64. */
  ciphertext: string;
  /** One wrapped content key per recipient. */
  recipients: WrappedKey[];
}

/**
 * Seal a message so that exactly the listed recipients can open it.
 *
 * Refuses rather than producing a partial envelope: if any recipient's key is
 * unusable the whole call fails. Sealing to the ones that worked would be the
 * "half-succeeded" shape — the caller sees an error while some members silently
 * never receive the message.
 */
export async function sealToMany(
  recipients: GroupRecipient[],
  plaintext: string
): Promise<SealedGroupEnvelope> {
  if (recipients.length === 0) {
    // A sealed message with no recipients is not a message. Producing one
    // silently would store ciphertext nobody can ever open, and nothing
    // downstream would notice until someone tried to read it.
    throw new ValidationError('A sealed group message needs at least one recipient.');
  }

  const seen = new Set<string>();
  for (const r of recipients) {
    if (seen.has(r.entity)) {
      // Deduplicating would hide a caller bug, and the second wrap would be
      // unreachable anyway because lookup takes the first.
      throw new ValidationError(`Duplicate recipient in sealed group message: ${r.entity}`);
    }
    seen.add(r.entity);
  }

  // One content key, one body encryption.
  const contentKeyBytes = crypto.getRandomValues(new Uint8Array(CONTENT_KEY_BYTES));
  const contentKey = await crypto.subtle.importKey(
    'raw',
    contentKeyBytes.buffer as ArrayBuffer,
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt']
  );

  const bodyIv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: bodyIv },
    contentKey,
    new TextEncoder().encode(plaintext)
  );

  // Wrap that key once per recipient. Every wrap is built before anything is
  // returned, so a bad key fails the whole call rather than yielding an
  // envelope some members cannot open.
  const wrapped: WrappedKey[] = [];
  for (const recipient of recipients) {
    wrapped.push(await wrapFor(recipient, contentKeyBytes));
  }

  return {
    version: GROUP_SEAL_VERSION,
    iv: bufferToBase64(bodyIv),
    ciphertext: bufferToBase64(new Uint8Array(ciphertext)),
    recipients: wrapped,
  };
}

/**
 * Open a group envelope as `entityId`.
 *
 * The entity id selects which wrapped key to try; the private key is what
 * actually opens it. Being listed is not sufficient and is not meant to be —
 * the list is a routing convenience, not an authorisation.
 */
export async function openGroup(
  entityId: string,
  recipientPrivateKeyBase64: string,
  envelope: SealedGroupEnvelope
): Promise<string> {
  if (envelope.version !== GROUP_SEAL_VERSION) {
    throw new SealedMessageError(
      `Sealed group envelope is version ${envelope.version}; this build handles version ${GROUP_SEAL_VERSION}.`
    );
  }

  const mine = envelope.recipients.find((r) => r.entity === entityId);
  if (!mine) {
    throw new SealedMessageError('This message was not sealed to you.');
  }

  const recipientPrivate = await crypto.subtle.importKey(
    'pkcs8',
    base64ToBuffer(recipientPrivateKeyBase64).buffer as ArrayBuffer,
    { name: 'X25519' },
    true,
    ['deriveBits']
  );
  const jwk = (await crypto.subtle.exportKey('jwk', recipientPrivate)) as unknown as {
    x?: string;
  };
  if (!jwk.x) {
    throw new SealedMessageError('Recipient private key did not yield its public half.');
  }
  const recipientPublicRaw = new Uint8Array(Buffer.from(jwk.x, 'base64url'));

  const ephemeralPublicRaw = base64ToBuffer(mine.ephemeralPublicKey);
  const ephemeralPublic = await crypto.subtle.importKey(
    'raw',
    ephemeralPublicRaw.buffer as ArrayBuffer,
    { name: 'X25519' },
    false,
    []
  );

  const binding = concat(ephemeralPublicRaw, recipientPublicRaw);
  const shared = await deriveShared(recipientPrivate, ephemeralPublic);
  const keyEncryptionKey = await deriveContentKey(shared, binding);

  let contentKeyBytes: ArrayBuffer;
  try {
    contentKeyBytes = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: tighten(base64ToBuffer(mine.iv)), additionalData: binding },
      keyEncryptionKey,
      base64ToBuffer(mine.wrappedKey).buffer as ArrayBuffer
    );
  } catch (cause) {
    // One message for "not your key" and "altered", as in sealing.ts: the two
    // are not distinguishable from the ciphertext, and a caller that could tell
    // them apart would hold an oracle for testing key ownership.
    throw new SealedMessageError(
      'Could not unwrap the content key — it was sealed to a different key, or it has been altered.',
      cause instanceof Error ? cause : undefined
    );
  }

  const contentKey = await crypto.subtle.importKey(
    'raw',
    contentKeyBytes,
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  );

  let body: ArrayBuffer;
  try {
    body = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: tighten(base64ToBuffer(envelope.iv)) },
      contentKey,
      base64ToBuffer(envelope.ciphertext).buffer as ArrayBuffer
    );
  } catch (cause) {
    throw new SealedMessageError(
      'Sealed group message body could not be opened — it has been altered.',
      cause instanceof Error ? cause : undefined
    );
  }

  return new TextDecoder().decode(body);
}

// ============================================================================
// Internals
// ============================================================================

/**
 * Seal the content key to one recipient, using the same ephemeral-static ECDH
 * as `sealing.ts` — a fresh ephemeral pair per recipient, so the wraps are
 * cryptographically independent. Damaging one leaves the others openable, which
 * is the property that makes per-recipient wrapping worth having at all.
 */
async function wrapFor(
  recipient: GroupRecipient,
  contentKeyBytes: Uint8Array
): Promise<WrappedKey> {
  let recipientPublic: CryptoKey;
  const recipientPublicRaw = base64ToBuffer(recipient.publicKey);
  try {
    recipientPublic = await crypto.subtle.importKey(
      'raw',
      recipientPublicRaw.buffer as ArrayBuffer,
      { name: 'X25519' },
      false,
      []
    );
  } catch (cause) {
    throw new ValidationError(
      `Recipient ${recipient.entity} has an unusable encryption key. ` +
        `Refusing to seal a message that entity could never open.`
    );
  }

  const ephemeral = (await crypto.subtle.generateKey({ name: 'X25519' }, true, [
    'deriveBits',
  ])) as unknown as CryptoKeyPair;
  const ephemeralPublicRaw = new Uint8Array(
    await crypto.subtle.exportKey('raw', ephemeral.publicKey)
  );

  const binding = concat(ephemeralPublicRaw, recipientPublicRaw);
  const shared = await deriveShared(ephemeral.privateKey, recipientPublic);
  const keyEncryptionKey = await deriveContentKey(shared, binding);

  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const wrapped = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: binding },
    keyEncryptionKey,
    contentKeyBytes.buffer as ArrayBuffer
  );

  return {
    entity: recipient.entity,
    ephemeralPublicKey: bufferToBase64(ephemeralPublicRaw),
    iv: bufferToBase64(iv),
    wrappedKey: bufferToBase64(new Uint8Array(wrapped)),
  };
}

/** See `sealing.ts`: BufferSource excludes SharedArrayBuffer-backed views. */
function concat(a: Uint8Array, b: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(new ArrayBuffer(a.length + b.length));
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function tighten(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(new ArrayBuffer(bytes.length));
  out.set(bytes);
  return out;
}
