// Message Encryption at Rest
//
// Encrypts message content in the database using AES-256-GCM.
// Uses HKDF to derive a key from the server secret.
//
// Rotation IS supported. Each envelope records `kid`, a non-reversible
// fingerprint of the secret that sealed it, so a message can say which key it
// needs. FAM_SERVER_SECRET_PREVIOUS holds retired secrets for reading; new
// messages always use FAM_SERVER_SECRET. `bun run rotate-key` re-seals
// everything onto the current key. See src/scripts/rotate-key.ts.
//
// Messages written while FAM_ENCRYPT_MESSAGES is disabled are stored as
// plaintext; enabling it later does not retroactively encrypt old rows (reads
// decrypt only when the flag is on, so mixed data must be avoided — pick a
// setting and keep it).

import { bufferToBase64, base64ToBuffer } from './argon2';
import { stampVersion, assertFormatSupported, type Versioned } from '../utils/versioning';
import { MessageKeyUnavailableError } from '../types/errors';

// ============================================================================
// Configuration
// ============================================================================

const IV_LENGTH = 12; // 96 bits for AES-GCM
const ALGORITHM = 'AES-GCM';
const KEY_LENGTH = 256;

// ============================================================================
// Key Derivation
// ============================================================================

// Keyed by secret: rotation means more than one is live at a time, so a single
// cached key would thrash between generations while a backlog is being read.
const keyCache = new Map<string, CryptoKey>();
const keyIdCache = new Map<string, string>();

/**
 * Derive an AES-256-GCM key from the server secret using HKDF.
 */
async function deriveKey(serverSecret: string): Promise<CryptoKey> {
  // Use a fixed salt for HKDF (derived from server secret hash)
  const cached = keyCache.get(serverSecret);
  if (cached) return cached;

  
  // Import the server secret as raw key material
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(serverSecret),
    'HKDF',
    false,
    ['deriveKey']
  );
  
  // Derive AES-256-GCM key
  const salt = encoder.encode('fam-message-encryption-salt-v1');
  const info = encoder.encode('fam-message-encryption-key');
  
  const derived = await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt,
      info,
    },
    keyMaterial,
    { name: ALGORITHM, length: KEY_LENGTH },
    false,
    ['encrypt', 'decrypt']
  );
  
  keyCache.set(serverSecret, derived);
  return derived;
}

/**
 * Find the key a stored message was sealed with.
 *
 * An envelope with no `kid` predates rotation, so the current secret is the
 * only candidate — that is the pre-rotation behaviour, preserved.
 */
async function resolveKeyFor(kid: string | undefined, keyring: Keyring): Promise<CryptoKey> {
  if (!kid) return deriveKey(keyring.current);

  for (const secret of [keyring.current, ...keyring.previous]) {
    if ((await keyIdFor(secret)) === kid) return deriveKey(secret);
  }

  throw new MessageKeyUnavailableError(kid);
}

// ============================================================================
// Keyring
// ============================================================================
export interface Keyring {
  /** The secret new messages are sealed with. */
  current: string;
  /** Retired secrets, kept only so messages sealed with them stay readable. */
  previous: string[];
}

function asKeyring(secretOrKeyring: string | Keyring): Keyring {
  return typeof secretOrKeyring === 'string'
    ? { current: secretOrKeyring, previous: [] }
    : secretOrKeyring;
}

/**
 * Build the keyring from the environment.
 *
 * FAM_SERVER_SECRET seals new messages. FAM_SERVER_SECRET_PREVIOUS is a
 * comma-separated list of retired secrets, kept ONLY so messages sealed with
 * them stay readable. Remove one and every message still sealed with it becomes
 * permanently unreadable — run `bun run rotate-key` first, then drop it.
 */
export function keyringFromEnv(): Keyring {
  const previous = (process.env.FAM_SERVER_SECRET_PREVIOUS ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  return { current: process.env.FAM_SERVER_SECRET ?? '', previous };
}

/**
 * A short, stable, non-reversible fingerprint of a secret.
 *
 * Travels in plaintext beside the ciphertext, so it is derived rather than
 * being any part of the secret itself.
 */
export async function keyIdFor(serverSecret: string): Promise<string> {
  const memo = keyIdCache.get(serverSecret);
  if (memo) return memo;

  const encoder = new TextEncoder();
  const material = await crypto.subtle.importKey(
    'raw',
    encoder.encode(serverSecret),
    'HKDF',
    false,
    ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: encoder.encode('fam-key-id-salt-v1'),
      info: encoder.encode('fam-key-id'),
    },
    material,
    64
  );
  const kid = bufferToBase64(new Uint8Array(bits)).replace(/[+/=]/g, '').slice(0, 10);
  keyIdCache.set(serverSecret, kid);
  return kid;
}

// ============================================================================
// Envelope Format
// ============================================================================

/**
 * Versioned ciphertext envelope stored in the messages.text column.
 * Legacy rows (pre-versioning) store raw base64 of IV||ciphertext with no
 * envelope — readers handle both.
 */
export interface CiphertextEnvelope extends Versioned {
  iv: string; // base64-encoded 96-bit IV
  ct: string; // base64-encoded ciphertext
  /**
   * Which key sealed this. Absent on envelopes written before rotation
   * existed — those predate any rotation, so the current secret is the only
   * candidate for them.
   */
  kid?: string;
}

/**
 * Detect whether a stored text is a versioned envelope or legacy raw bytes.
 */
function parseEnvelope(stored: string): CiphertextEnvelope | null {
  if (!stored.startsWith('{')) return null;
  try {
    const parsed = JSON.parse(stored) as CiphertextEnvelope;
    if (typeof parsed.iv !== 'string' || typeof parsed.ct !== 'string') return null;
    return parsed;
  } catch {
    return null;
  }
}

// ============================================================================
// Encryption
// ============================================================================

/**
 * Encrypt message text using AES-256-GCM.
 * Returns a JSON envelope (versioned) with base64 IV and ciphertext.
 */
export async function encryptMessage(
  plaintext: string,
  serverSecret: string | Keyring
): Promise<string> {
  const keyring = asKeyring(serverSecret);
  const key = await deriveKey(keyring.current);
  const kid = await keyIdFor(keyring.current);
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));

  const encoder = new TextEncoder();
  const plaintextBuffer = encoder.encode(plaintext);

  const ciphertext = await crypto.subtle.encrypt(
    { name: ALGORITHM, iv },
    key,
    plaintextBuffer
  );

  const envelope: CiphertextEnvelope = stampVersion({
    iv: bufferToBase64(iv),
    ct: bufferToBase64(new Uint8Array(ciphertext)),
    kid,
  });

  return JSON.stringify(envelope);
}

// ============================================================================
// Decryption
// ============================================================================

/**
 * Decrypt message text using AES-256-GCM.
 * Accepts the versioned JSON envelope or the legacy raw IV||ciphertext format.
 */
export async function decryptMessage(
  ciphertextBase64: string,
  serverSecret: string | Keyring
): Promise<string> {
  const keyring = asKeyring(serverSecret);

  let iv: Uint8Array<ArrayBuffer>;
  let ciphertext: Uint8Array<ArrayBuffer>;
  let key: CryptoKey;

  const envelope = parseEnvelope(ciphertextBase64);
  if (envelope) {
    assertFormatSupported(envelope, 'Message ciphertext envelope');
    iv = new Uint8Array(base64ToBuffer(envelope.iv));
    ciphertext = new Uint8Array(base64ToBuffer(envelope.ct));
    key = await resolveKeyFor(envelope.kid, keyring);
  } else {
    // Legacy format: raw base64 of IV||ciphertext
    const combined = base64ToBuffer(ciphertextBase64);
    iv = new Uint8Array(combined.slice(0, IV_LENGTH));
    ciphertext = new Uint8Array(combined.slice(IV_LENGTH));
    // Raw legacy bytes carry no key identity either.
    key = await resolveKeyFor(undefined, keyring);
  }

  const decrypted = await crypto.subtle.decrypt(
    { name: ALGORITHM, iv },
    key,
    ciphertext
  );

  const decoder = new TextDecoder();
  return decoder.decode(decrypted);
}

// ============================================================================
// Batch Operations
// ============================================================================

/**
 * Encrypt multiple messages.
 */
export async function encryptMessages(
  messages: Array<{ id: number; text: string }>,
  serverSecret: string
): Promise<Array<{ id: number; encrypted_text: string }>> {
  return Promise.all(
    messages.map(async (msg) => ({
      id: msg.id,
      encrypted_text: await encryptMessage(msg.text, serverSecret),
    }))
  );
}

/**
 * Decrypt multiple messages.
 */
export async function decryptMessages(
  messages: Array<{ id: number; text: string }>,
  serverSecret: string
): Promise<Array<{ id: number; text: string }>> {
  return Promise.all(
    messages.map(async (msg) => ({
      id: msg.id,
      text: await decryptMessage(msg.text, serverSecret),
    }))
  );
}
