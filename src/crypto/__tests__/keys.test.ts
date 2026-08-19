import { test, expect, describe } from 'bun:test';
import {
  generateKeyPair,
  sign,
  verify,
  bufferToBase64,
  base64ToBuffer,
  generateNonce,
} from '../keys';

describe('Key Generation', () => {
  test('generates valid Ed25519 key pair', async () => {
    const keyPair = await generateKeyPair();

    expect(keyPair.publicKey).toBeDefined();
    expect(keyPair.privateKey).toBeDefined();
    expect(keyPair.publicKey).toBeInstanceOf(Uint8Array);
    expect(keyPair.privateKey).toBeInstanceOf(Uint8Array);
    expect(keyPair.publicKey.length).toBe(32);
    expect(keyPair.privateKey.length).toBeGreaterThan(0);
  });

  test('generates unique key pairs', async () => {
    const keyPair1 = await generateKeyPair();
    const keyPair2 = await generateKeyPair();

    expect(keyPair1.publicKey).not.toEqual(keyPair2.publicKey);
    expect(keyPair1.privateKey).not.toEqual(keyPair2.privateKey);
  });
});

describe('Sign and Verify', () => {
  test('signs and verifies message successfully', async () => {
    const keyPair = await generateKeyPair();
    const message = new TextEncoder().encode('test message');

    const signature = await sign(message, bufferToBase64(keyPair.privateKey));
    const valid = await verify(message, signature, bufferToBase64(keyPair.publicKey));

    expect(typeof signature).toBe('string');
    expect(valid).toBe(true);
  });

  test('fails verification with wrong public key', async () => {
    const keyPair1 = await generateKeyPair();
    const keyPair2 = await generateKeyPair();
    const message = new TextEncoder().encode('test message');

    const signature = await sign(message, bufferToBase64(keyPair1.privateKey));
    const valid = await verify(message, signature, bufferToBase64(keyPair2.publicKey));

    expect(valid).toBe(false);
  });

  test('fails verification with wrong message', async () => {
    const keyPair = await generateKeyPair();
    const message = new TextEncoder().encode('test message');
    const wrongMessage = new TextEncoder().encode('wrong message');

    const signature = await sign(message, bufferToBase64(keyPair.privateKey));
    const valid = await verify(wrongMessage, signature, bufferToBase64(keyPair.publicKey));

    expect(valid).toBe(false);
  });
});

describe('Base64 Conversion', () => {
  test('converts buffer to base64 and back', () => {
    const original = new Uint8Array([1, 2, 3, 4, 5]);
    const base64 = bufferToBase64(original);
    const restored = base64ToBuffer(base64);

    expect(typeof base64).toBe('string');
    expect(restored).toEqual(original);
  });

  test('handles empty buffer', () => {
    const original = new Uint8Array([]);
    const base64 = bufferToBase64(original);
    const restored = base64ToBuffer(base64);

    expect(restored).toEqual(original);
  });
});

describe('Nonce Generation', () => {
  test('generates random nonce', () => {
    const nonce = generateNonce();

    expect(typeof nonce).toBe('string');
    expect(nonce.length).toBeGreaterThan(0);
  });

  test('generates unique nonces', () => {
    const nonce1 = generateNonce();
    const nonce2 = generateNonce();

    expect(nonce1).not.toBe(nonce2);
  });
});
