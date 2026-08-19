import { test, expect, describe } from 'bun:test';
import {
  encryptPrivateKey,
  decryptPrivateKey,
} from '../encrypt';
import { generateKeyPair, bufferToBase64 } from '../keys';
import type { EncryptedKeyFile } from '../../types';

describe('Encryption', () => {
  test('encrypts and decrypts private key', async () => {
    const keyPair = await generateKeyPair();
    const passkey = 'test-passphrase-123';
    const privateKeyBase64 = bufferToBase64(keyPair.privateKey);
    const publicKeyBase64 = bufferToBase64(keyPair.publicKey);

    const encrypted = await encryptPrivateKey(privateKeyBase64, passkey, 'test@test.com', publicKeyBase64);
    const decrypted = await decryptPrivateKey(encrypted, passkey);

    expect(encrypted).toBeDefined();
    expect(encrypted.entity_id).toBe('test@test.com');
    expect(encrypted.public_key).toBe(publicKeyBase64);
    expect(encrypted.kdf).toBe('argon2id');
    expect(encrypted.encryption).toBe('aes-256-gcm');
    expect(decrypted).toBe(privateKeyBase64);
  }, 15000);

  test('fails decryption with wrong passkey', async () => {
    const keyPair = await generateKeyPair();
    const passkey = 'correct-passphrase';
    const wrongPasskey = 'wrong-passphrase';
    const privateKeyBase64 = bufferToBase64(keyPair.privateKey);
    const publicKeyBase64 = bufferToBase64(keyPair.publicKey);

    const encrypted = await encryptPrivateKey(privateKeyBase64, passkey, 'test@test.com', publicKeyBase64);

    await expect(decryptPrivateKey(encrypted, wrongPasskey)).rejects.toThrow();
  }, 15000);

  test('produces different ciphertext with different passkeys', async () => {
    const keyPair = await generateKeyPair();
    const passkey1 = 'passphrase-1';
    const passkey2 = 'passphrase-2';
    const privateKeyBase64 = bufferToBase64(keyPair.privateKey);
    const publicKeyBase64 = bufferToBase64(keyPair.publicKey);

    const encrypted1 = await encryptPrivateKey(privateKeyBase64, passkey1, 'test@test.com', publicKeyBase64);
    const encrypted2 = await encryptPrivateKey(privateKeyBase64, passkey2, 'test@test.com', publicKeyBase64);

    expect(encrypted1.encrypted_private_key).not.toBe(encrypted2.encrypted_private_key);
  }, 15000);
});
