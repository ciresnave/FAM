import { test, expect, describe } from 'bun:test';
import { encryptMessage, decryptMessage } from '../message-encryption';

const SECRET = 'test-server-secret-for-message-encryption';

describe('Message Encryption at Rest', () => {
  test('encrypts and decrypts message', async () => {
    const plaintext = 'Hello, secret world!';
    const ciphertext = await encryptMessage(plaintext, SECRET);

    expect(ciphertext).toBeDefined();
    expect(ciphertext).not.toBe(plaintext);

    const decrypted = await decryptMessage(ciphertext, SECRET);
    expect(decrypted).toBe(plaintext);
  });

  test('produces different ciphertext for same plaintext (random IV)', async () => {
    const plaintext = 'same message';
    const c1 = await encryptMessage(plaintext, SECRET);
    const c2 = await encryptMessage(plaintext, SECRET);

    expect(c1).not.toBe(c2);

    // Both decrypt to the same plaintext
    expect(await decryptMessage(c1, SECRET)).toBe(plaintext);
    expect(await decryptMessage(c2, SECRET)).toBe(plaintext);
  });

  test('fails decryption with wrong secret', async () => {
    const plaintext = 'secret message';
    const ciphertext = await encryptMessage(plaintext, SECRET);

    expect(decryptMessage(ciphertext, 'wrong-secret')).rejects.toThrow();
  });

  test('handles empty string', async () => {
    const ciphertext = await encryptMessage('', SECRET);
    const decrypted = await decryptMessage(ciphertext, SECRET);
    expect(decrypted).toBe('');
  });

  test('handles unicode and long text', async () => {
    const plaintext = 'héllo wörld 🌍 '.repeat(100);
    const ciphertext = await encryptMessage(plaintext, SECRET);
    const decrypted = await decryptMessage(ciphertext, SECRET);
    expect(decrypted).toBe(plaintext);
  });
});
