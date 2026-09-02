// End-to-end message sealing — confidentiality FROM THE RELAY.
//
// ─────────────────────────────────────────────────────────────────────────────
// THIS IS NOT `message-encryption.ts`, AND THE DIFFERENCE IS THE POINT.
//
// That module encrypts message rows at rest under a key derived from
// FAM_SERVER_SECRET. The server holds that secret, so the server reads every
// message. It defends a stolen disk and gives ZERO confidentiality from the
// relay. Both are wanted; they are not substitutes, and the older one's NAME
// matches the requirement closely enough to silence the question. Keep saying
// under whose key a thing is encrypted.
// ─────────────────────────────────────────────────────────────────────────────
//
// CONSTRUCTION: ephemeral-static ECDH, the sealed-box shape (libsodium's
// crypto_box_seal). The sender makes a throwaway X25519 pair per message,
// derives a shared secret against the recipient's long-term public key, and
// ships the ephemeral public key in the envelope. Both public keys go into the
// HKDF salt and the GCM additional data, so a ciphertext is bound to the exact
// pair of keys it was made for.
//
// TWO CONSEQUENCES, both intended:
//
//   The sender needs no long-term encryption key. Only the recipient's public
//   one. There is nothing to distribute in the send direction.
//
//   Sealing says NOTHING about who sent it. Anyone holding a public key can
//   seal to it. Authenticity is the Ed25519 signature over the envelope — a
//   separate half, deliberately. This module is confidentiality only, and a
//   reader who assumes otherwise gets an unauthenticated message.

import { bufferToBase64, base64ToBuffer } from './keys';
import { SealedMessageError } from '../types/errors';

const SEAL_VERSION = 1;
const IV_LENGTH = 12; // 96 bits, the AES-GCM standard nonce size
const SHARED_SECRET_BITS = 256;
const HKDF_INFO = 'fam-message-seal-v1';

/**
 * The one JWK field this module reads: `x`, the public half of an X25519 key.
 *
 * Declared locally rather than using the DOM lib's `JsonWebKey` — tsconfig sets
 * `lib: ["ES2022"]` with `types: ["bun-types"]` and no DOM, so that name does
 * not exist here. Widening the lib to reach one field would change resolution
 * for every file in the project.
 */
interface JwkPublicHalf {
  x?: string;
}

export interface SealedEnvelope {
  /** Envelope format version, so a later construction can be told apart. */
  version: number;
  /** Raw X25519 public key of the per-message ephemeral pair, base64. */
  ephemeralPublicKey: string;
  /** AES-GCM nonce, base64. Fresh per message. */
  iv: string;
  /** AES-256-GCM ciphertext including the authentication tag, base64. */
  ciphertext: string;
}

/**
 * Seal a message to a recipient's X25519 public key.
 *
 * The result can be opened only by the holder of the matching private key, and
 * carries no indication of who produced it.
 */
export async function seal(
  recipientPublicKeyBase64: string,
  plaintext: string
): Promise<SealedEnvelope> {
  const recipientPublicRaw = base64ToBuffer(recipientPublicKeyBase64);
  const recipientPublic = await importPublic(recipientPublicRaw);

  const ephemeral = (await crypto.subtle.generateKey({ name: 'X25519' }, true, [
    'deriveBits',
  ])) as unknown as CryptoKeyPair;
  const ephemeralPublicRaw = new Uint8Array(
    await crypto.subtle.exportKey('raw', ephemeral.publicKey)
  );

  const shared = await deriveShared(ephemeral.privateKey, recipientPublic);
  const binding = concat(ephemeralPublicRaw, recipientPublicRaw);
  const key = await deriveContentKey(shared, binding);

  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: binding },
    key,
    new TextEncoder().encode(plaintext)
  );

  return {
    version: SEAL_VERSION,
    ephemeralPublicKey: bufferToBase64(ephemeralPublicRaw),
    iv: bufferToBase64(iv),
    ciphertext: bufferToBase64(new Uint8Array(ciphertext)),
  };
}

/**
 * Open an envelope with the recipient's X25519 private key.
 *
 * Throws if the envelope was sealed to a different key or has been altered —
 * AES-GCM authenticates, so a tampered ciphertext is refused rather than
 * returned mangled.
 */
export async function open(
  recipientPrivateKeyBase64: string,
  envelope: SealedEnvelope
): Promise<string> {
  if (envelope.version !== SEAL_VERSION) {
    throw new SealedMessageError(
      `Sealed envelope is version ${envelope.version}; this build seals and opens version ${SEAL_VERSION}.`
    );
  }

  // Extractable, because the recipient's own PUBLIC key is half the binding and
  // the caller supplies only the private half. Recovering it from `d` is how
  // the recipient knows which key the sender sealed to. Verified on Bun 1.3.14:
  // the `x` field of the exported JWK matches the raw public key exactly.
  const recipientPrivate = await crypto.subtle.importKey(
    'pkcs8',
    base64ToBuffer(recipientPrivateKeyBase64).buffer as ArrayBuffer,
    { name: 'X25519' },
    true,
    ['deriveBits']
  );
  const jwk = (await crypto.subtle.exportKey('jwk', recipientPrivate)) as unknown as JwkPublicHalf;
  if (!jwk.x) {
    throw new SealedMessageError('Recipient private key did not yield its public half.');
  }
  const recipientPublicRaw = new Uint8Array(Buffer.from(jwk.x, 'base64url'));

  const ephemeralPublicRaw = base64ToBuffer(envelope.ephemeralPublicKey);
  const ephemeralPublic = await importPublic(ephemeralPublicRaw);

  const shared = await deriveShared(recipientPrivate, ephemeralPublic);
  const binding = concat(ephemeralPublicRaw, recipientPublicRaw);
  const key = await deriveContentKey(shared, binding);

  let plaintext: ArrayBuffer;
  try {
    plaintext = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: tighten(base64ToBuffer(envelope.iv)),
        additionalData: binding,
      },
      key,
      base64ToBuffer(envelope.ciphertext).buffer as ArrayBuffer
    );
  } catch (cause) {
    // One message for "not yours" and "altered", because the two are not
    // distinguishable from the ciphertext and pretending otherwise would invent
    // an oracle: a caller who could tell them apart could test key ownership.
    throw new SealedMessageError(
      'Sealed message could not be opened — it was sealed to a different key, or it has been altered.',
      cause instanceof Error ? cause : undefined
    );
  }

  return new TextDecoder().decode(plaintext);
}

// ============================================================================
// The cryptographic seam
//
// These two are exported deliberately, for a reason found by mutation testing
// rather than anticipated.
//
// TWO MUTANTS BOTH SURVIVED THE FULL BLACK-BOX SUITE:
//
//   1. content key derived from 32 zero bytes instead of the ECDH secret
//   2. the public-key binding dropped from the HKDF salt and the GCM AAD
//
// Mutant 1 is a TOTAL BREAK — every remaining KDF input is public, so anyone
// holding the envelope derives the key — and all ten tests passed. The test
// that should have caught it, "a different key cannot open it", passes because
// the mutant's salt still contains the recipient's public key, so a different
// recipient still derives a different key. IT PASSED FOR A REASON UNRELATED TO
// THE PROPERTY IT NAMES. Mutant 2 survives symmetrically: each mutant is masked
// by the half the other one keeps.
//
// No test written against seal/open can separate them, because the API never
// offers the operation that distinguishes them — deriving a key from public
// inputs alone. So the seam is tested directly, and is exported to make that
// possible. It is not test-only surface: the per-recipient content-key wrapping
// for channel messages needs both of these too.
// ============================================================================

async function importPublic(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', raw.buffer as ArrayBuffer, { name: 'X25519' }, false, []);
}

export async function deriveShared(
  privateKey: CryptoKey,
  publicKey: CryptoKey
): Promise<ArrayBuffer> {
  // The algorithm object carries `public`, which bun-types' deriveBits
  // signature does not model. Cast to that parameter's own type rather than to
  // the DOM's `AlgorithmIdentifier`, which this tsconfig does not include.
  return crypto.subtle.deriveBits(
    { name: 'X25519', public: publicKey } as unknown as Parameters<
      typeof crypto.subtle.deriveBits
    >[0],
    privateKey,
    SHARED_SECRET_BITS
  );
}

/**
 * HKDF the raw ECDH output into an AES-256-GCM key.
 *
 * The raw shared secret is NOT used as a key directly: it is a curve point,
 * not uniformly random, and every construction that skips this step regrets it.
 * `binding` is both HKDF salt and GCM additional data, so the key and the
 * ciphertext are each tied to the specific pair of public keys.
 */
export async function deriveContentKey(
  shared: ArrayBuffer,
  binding: Uint8Array<ArrayBuffer>
): Promise<CryptoKey> {
  const ikm = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: binding,
      info: new TextEncoder().encode(HKDF_INFO),
    },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Concatenate into a Uint8Array backed by a plain ArrayBuffer.
 *
 * The return type is not decoration. WebCrypto's `BufferSource` excludes
 * SharedArrayBuffer-backed views, so a `Uint8Array<ArrayBufferLike>` — what the
 * bare constructor and `base64ToBuffer` both produce — is rejected wherever it
 * is passed as an IV, a salt, or additional data.
 */
function concat(a: Uint8Array, b: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(new ArrayBuffer(a.length + b.length));
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/** Same reason as `concat`: re-back a decoded buffer with a plain ArrayBuffer. */
function tighten(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(new ArrayBuffer(bytes.length));
  out.set(bytes);
  return out;
}
