// Argon2id Key Derivation using @noble/hashes
//
// This provides the actual Argon2id implementation for private key encryption.

// @ts-ignore - @noble/hashes doesn't have type declarations
import { argon2id } from '@noble/hashes/argon2.js';
// @ts-ignore
import { randomBytes } from '@noble/hashes/utils.js';

// ============================================================================
// Types
// ============================================================================

export interface Argon2Params {
  memory: number;    // in KiB (e.g., 65536 = 64 MB)
  iterations: number;
  parallelism: number;
}

// ============================================================================
// Constants
// ============================================================================

export const DEFAULT_ARGON2_PARAMS: Argon2Params = {
  memory: 65536,    // 64 MB
  iterations: 3,
  parallelism: 4,
};

export const SALT_LENGTH = 16; // 128 bits
export const KEY_LENGTH = 32;  // 256 bits for AES-256

// ============================================================================
// Key Derivation
// ============================================================================

/**
 * Derive a key from a password using Argon2id.
 * 
 * @param password - The password to derive key from
 * @param salt - The salt (generate with generateSalt() if needed)
 * @param params - Argon2 parameters
 * @returns Derived key as Uint8Array (32 bytes)
 */
export function deriveKeyArgon2id(
  password: string,
  salt: Uint8Array,
  params: Argon2Params = DEFAULT_ARGON2_PARAMS
): Uint8Array {
  return argon2id(password, salt, {
    m: params.memory,
    t: params.iterations,
    p: params.parallelism,
    dkLen: KEY_LENGTH,
  });
}

/**
 * Generate a cryptographically secure random salt.
 */
export function generateSalt(): Uint8Array {
  return randomBytes(SALT_LENGTH);
}

/**
 * Derive key and return both key and salt (for storage).
 */
export function deriveKeyWithSalt(
  password: string,
  params: Argon2Params = DEFAULT_ARGON2_PARAMS
): { key: Uint8Array; salt: Uint8Array } {
  const salt = generateSalt();
  const key = deriveKeyArgon2id(password, salt, params);
  return { key, salt };
}

// ============================================================================
// Utility Functions
// ============================================================================

export function bufferToBase64(buffer: Uint8Array): string {
  return Buffer.from(buffer).toString('base64');
}

export function base64ToBuffer(base64: string): Uint8Array {
  return new Uint8Array(Buffer.from(base64, 'base64'));
}
