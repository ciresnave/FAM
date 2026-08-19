// Ed25519 Key Pair Generation and Management

// ============================================================================
// Types
// ============================================================================

export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export interface SerializedKeyPair {
  publicKey: string; // base64-encoded
  privateKey: string; // base64-encoded
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Convert a Uint8Array to a base64 string.
 */
export function bufferToBase64(buffer: Uint8Array): string {
  return Buffer.from(buffer).toString('base64');
}

/**
 * Convert a base64 string to a Uint8Array.
 */
export function base64ToBuffer(base64: string): Uint8Array {
  return new Uint8Array(Buffer.from(base64, 'base64'));
}

// ============================================================================
// Key Generation
// ============================================================================

/**
 * Generate a new Ed25519 key pair for entity authentication.
 * Uses Web Crypto API which is built into Bun.
 */
export async function generateKeyPair(): Promise<KeyPair> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'Ed25519',
      namedCurve: 'Ed25519',
    },
    true, // extractable
    ['sign', 'verify']
  );

  const publicKeyBuffer = await crypto.subtle.exportKey('raw', keyPair.publicKey);
  const privateKeyBuffer = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);

  return {
    publicKey: new Uint8Array(publicKeyBuffer),
    privateKey: new Uint8Array(privateKeyBuffer),
  };
}

/**
 * Generate a key pair and return base64-encoded strings.
 */
export async function generateSerializedKeyPair(): Promise<SerializedKeyPair> {
  const keyPair = await generateKeyPair();
  return {
    publicKey: bufferToBase64(keyPair.publicKey),
    privateKey: bufferToBase64(keyPair.privateKey),
  };
}

// ============================================================================
// Signing & Verification
// ============================================================================

/**
 * Sign data with a private key.
 */
export async function sign(
  data: Uint8Array,
  privateKeyBase64: string
): Promise<string> {
  const privateKeyBytes = base64ToBuffer(privateKeyBase64);
  
  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    privateKeyBytes.buffer as ArrayBuffer,
    { name: 'Ed25519', namedCurve: 'Ed25519' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign(
    { name: 'Ed25519' },
    privateKey,
    data.buffer as ArrayBuffer
  );

  return bufferToBase64(new Uint8Array(signature));
}

/**
 * Verify a signature with a public key.
 */
export async function verify(
  data: Uint8Array,
  signatureBase64: string,
  publicKeyBase64: string
): Promise<boolean> {
  const signature = base64ToBuffer(signatureBase64);
  const publicKeyBytes = base64ToBuffer(publicKeyBase64);

  const publicKey = await crypto.subtle.importKey(
    'raw',
    publicKeyBytes.buffer as ArrayBuffer,
    { name: 'Ed25519', namedCurve: 'Ed25519' },
    false,
    ['verify']
  );

  return crypto.subtle.verify(
    { name: 'Ed25519' },
    publicKey,
    signature.buffer as ArrayBuffer,
    data.buffer as ArrayBuffer
  );
}

// ============================================================================
// Nonce Generation (for challenge-response)
// ============================================================================

const NONCE_LENGTH = 32;

/**
 * Generate a cryptographically secure random nonce.
 */
export function generateNonce(length: number = NONCE_LENGTH): string {
  const nonce = crypto.getRandomValues(new Uint8Array(length));
  return bufferToBase64(nonce);
}

/**
 * Hash data using SHA-256 (for token hashing, etc.).
 */
export async function hashSha256(data: string): Promise<string> {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
  return bufferToBase64(new Uint8Array(hashBuffer));
}
