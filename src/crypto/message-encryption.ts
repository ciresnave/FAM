// Message Encryption at Rest
//
// Encrypts message content in the database using AES-256-GCM.
// Uses HKDF to derive a key from the server secret.
//
// NOTE: No key rotation support yet. Rotating FAM_SERVER_SECRET makes all
// previously encrypted messages undecryptable. Messages written while
// FAM_ENCRYPT_MESSAGES is disabled are stored as plaintext; enabling it
// later does not retroactively encrypt old rows (reads decrypt only when
// the flag is on, so mixed data must be avoided — pick a setting and keep it).

import { bufferToBase64, base64ToBuffer } from './argon2';
import { stampVersion, assertFormatSupported, type Versioned } from '../utils/versioning';

// ============================================================================
// Configuration
// ============================================================================

const IV_LENGTH = 12; // 96 bits for AES-GCM
const ALGORITHM = 'AES-GCM';
const KEY_LENGTH = 256;

// ============================================================================
// Key Derivation
// ============================================================================

let cachedKey: CryptoKey | null = null;
let cachedSalt: string | null = null;

/**
 * Derive an AES-256-GCM key from the server secret using HKDF.
 */
async function deriveKey(serverSecret: string): Promise<CryptoKey> {
  // Use a fixed salt for HKDF (derived from server secret hash)
  if (cachedKey && cachedSalt === serverSecret) {
    return cachedKey;
  }
  
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
  
  cachedKey = await crypto.subtle.deriveKey(
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
  
  cachedSalt = serverSecret;
  return cachedKey;
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
  serverSecret: string
): Promise<string> {
  const key = await deriveKey(serverSecret);
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
  serverSecret: string
): Promise<string> {
  const key = await deriveKey(serverSecret);

  let iv: Uint8Array<ArrayBuffer>;
  let ciphertext: Uint8Array<ArrayBuffer>;

  const envelope = parseEnvelope(ciphertextBase64);
  if (envelope) {
    assertFormatSupported(envelope, 'Message ciphertext envelope');
    iv = new Uint8Array(base64ToBuffer(envelope.iv));
    ciphertext = new Uint8Array(base64ToBuffer(envelope.ct));
  } else {
    // Legacy format: raw base64 of IV||ciphertext
    const combined = base64ToBuffer(ciphertextBase64);
    iv = new Uint8Array(combined.slice(0, IV_LENGTH));
    ciphertext = new Uint8Array(combined.slice(IV_LENGTH));
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
