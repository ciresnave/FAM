import { test, expect, describe } from 'bun:test';
import {
  encryptPrivateKey,
  decryptPrivateKey,
} from '../encrypt';
import { generateKeyPair, bufferToBase64 } from '../keys';
import type { EncryptedKeyFile } from '../../types';

// These tests are the slowest in the suite: Argon2id at 64MB/t=3/p=4, twice
// each (encrypt + decrypt, or two encrypts). Roughly 3-4s apiece in isolation.
//
// They used to carry an explicit `}, 15000)` — the ONLY per-test timeout
// overrides in the whole codebase — which SILENTLY UNDID the project-wide
// `--timeout 60000` that package.json sets for exactly this reason. A local
// override below the global default, on the tests that need headroom most.
//
// The result was an intermittent failure at ~18s: over the 15s local budget,
// far under the 60s the project intended. Twice in roughly six full-suite runs,
// never reproducible on demand, and passing 3/3 in isolation — because in
// isolation there is no contention for 64MB allocations.
//
// The failure mode this created was worse than a slow test. `fails decryption
// with wrong passkey` going red READS as a negative control passing — as
// decryption succeeding with the wrong key — when it actually meant the test
// was killed before the assertion ran. A timeout on a security test is
// indistinguishable at a glance from that test discovering something terrible.
//
// Not fixed by raising 15000 to some larger number: fixed by deleting an
// override that should not have existed, so these inherit the project default
// like every other test.

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
  });

  test('fails decryption with wrong passkey', async () => {
    const keyPair = await generateKeyPair();
    const passkey = 'correct-passphrase';
    const wrongPasskey = 'wrong-passphrase';
    const privateKeyBase64 = bufferToBase64(keyPair.privateKey);
    const publicKeyBase64 = bufferToBase64(keyPair.publicKey);

    const encrypted = await encryptPrivateKey(privateKeyBase64, passkey, 'test@test.com', publicKeyBase64);

    await expect(decryptPrivateKey(encrypted, wrongPasskey)).rejects.toThrow();
  });

  test('produces different ciphertext with different passkeys', async () => {
    const keyPair = await generateKeyPair();
    const passkey1 = 'passphrase-1';
    const passkey2 = 'passphrase-2';
    const privateKeyBase64 = bufferToBase64(keyPair.privateKey);
    const publicKeyBase64 = bufferToBase64(keyPair.publicKey);

    const encrypted1 = await encryptPrivateKey(privateKeyBase64, passkey1, 'test@test.com', publicKeyBase64);
    const encrypted2 = await encryptPrivateKey(privateKeyBase64, passkey2, 'test@test.com', publicKeyBase64);

    expect(encrypted1.encrypted_private_key).not.toBe(encrypted2.encrypted_private_key);
  });
});
