// Encryption Utilities for Private Key Storage
// Uses Argon2id for key derivation and AES-GCM for encryption

import { deriveKeyArgon2id, generateSalt, bufferToBase64, base64ToBuffer, DEFAULT_ARGON2_PARAMS } from './argon2';
import type { KdfParams, EncryptedKeyFile } from '../types';
import { stampVersion, assertFormatSupported } from '../utils/versioning';

// ============================================================================
// Constants
// ============================================================================

const IV_LENGTH = 12; // 96 bits for AES-GCM

// ============================================================================
// Encryption
// ============================================================================

/**
 * Encrypt a private key using a password.
 * Returns the encrypted key file structure.
 */
export async function encryptPrivateKey(
  privateKeyBase64: string,
  password: string,
  entityId: string,
  publicKeyBase64: string
): Promise<EncryptedKeyFile> {
  // Generate salt using Argon2id utility
  const salt = generateSalt();
  
  // Derive encryption key from password using Argon2id
  const derivedKey = deriveKeyArgon2id(password, salt, DEFAULT_ARGON2_PARAMS);
  
  // Import derived key for AES-GCM
  const encryptionKey = await crypto.subtle.importKey(
    'raw',
    derivedKey.buffer as ArrayBuffer,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );
  
  // Generate IV
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  
  // Encrypt private key
  const encoder = new TextEncoder();
  const privateKeyBuffer = encoder.encode(privateKeyBase64);
  
  const encryptedBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    encryptionKey,
    privateKeyBuffer
  );
  
  // Combine IV + encrypted data
  const combined = new Uint8Array(iv.length + encryptedBuffer.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(encryptedBuffer), iv.length);
  
  return stampVersion({
    entity_id: entityId,
    public_key: publicKeyBase64,
    encrypted_private_key: bufferToBase64(combined),
    kdf: 'argon2id',
    kdf_params: {
      memory: DEFAULT_ARGON2_PARAMS.memory,
      iterations: DEFAULT_ARGON2_PARAMS.iterations,
      parallelism: DEFAULT_ARGON2_PARAMS.parallelism,
      salt: bufferToBase64(salt),
    },
    encryption: 'aes-256-gcm',
  });
}

// ============================================================================
// Decryption
// ============================================================================

/**
 * Decrypt a private key using a password.
 * Returns the base64-encoded private key.
 */
export async function decryptPrivateKey(
  encryptedKeyFile: EncryptedKeyFile,
  password: string
): Promise<string> {
  // Reject key files written by a newer FAM before attempting to parse them
  assertFormatSupported(encryptedKeyFile, 'EncryptedKeyFile');

  const { encrypted_private_key, kdf_params } = encryptedKeyFile;
  
  // Decode salt and encrypted data
  const salt = base64ToBuffer(kdf_params.salt);
  const combined = base64ToBuffer(encrypted_private_key);
  
  // Extract IV and encrypted data
  const iv = combined.slice(0, IV_LENGTH);
  const encryptedData = combined.slice(IV_LENGTH);
  
  // Derive decryption key from password using Argon2id
  const derivedKey = deriveKeyArgon2id(password, salt, {
    memory: kdf_params.memory,
    iterations: kdf_params.iterations,
    parallelism: kdf_params.parallelism,
  });
  
  // Import derived key for AES-GCM
  const decryptionKey = await crypto.subtle.importKey(
    'raw',
    derivedKey.buffer as ArrayBuffer,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
  
  // Decrypt
  const decryptedBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    decryptionKey,
    encryptedData.buffer as ArrayBuffer
  );
  
  // Convert to string
  const decoder = new TextDecoder();
  return decoder.decode(decryptedBuffer);
}

// ============================================================================
// Validation
// ============================================================================

/**
 * Validate that a password can decrypt the key file.
 * Returns true if successful, false otherwise.
 */
export async function validatePassword(
  encryptedKeyFile: EncryptedKeyFile,
  password: string
): Promise<boolean> {
  try {
    await decryptPrivateKey(encryptedKeyFile, password);
    return true;
  } catch (e) {
    // Only catch decryption failures, re-throw other errors
    if (e instanceof DOMException && e.name === 'OperationError') {
      return false;
    }
    throw e;
  }
}
