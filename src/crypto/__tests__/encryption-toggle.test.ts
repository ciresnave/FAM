import { test, expect, describe } from 'bun:test';
import {
  encryptMessage,
  decryptMessage,
  looksLikeCiphertextEnvelope,
  assertNotSealed,
} from '../message-encryption';

// ============================================================================
// FAM_ENCRYPT_MESSAGES is a boolean env var over a database that may already
// hold rows written under the other setting. Flipping it has two failure modes
// and neither was covered:
//
//   ON over plaintext rows  -> DOMException "The provided data is too small".
//                              Accurate, useless, and indistinguishable from
//                              corruption or a wrong key.
//   OFF over ciphertext rows -> SILENT. The repository skips decryption and the
//                              raw JSON envelope is handed to the caller AS THE
//                              MESSAGE TEXT.
//
// The silent one is the worse one: it presents ciphertext to a human as if it
// were what someone wrote.
// ============================================================================

const SECRET = 'toggle-test-secret-aaaaaaaaaaaaaaaaaaaa';

describe('detecting ciphertext handed back as plaintext', () => {
  test('recognises a real envelope', async () => {
    const sealed = await encryptMessage('hello', SECRET);
    expect(looksLikeCiphertextEnvelope(sealed)).toBe(true);
  });

  test('ordinary text is not mistaken for an envelope', () => {
    expect(looksLikeCiphertextEnvelope('just a message')).toBe(false);
    expect(looksLikeCiphertextEnvelope('')).toBe(false);
  });

  // A user may legitimately send JSON as their message. Detection keys on the
  // full envelope shape INCLUDING `version`, which encryptMessage stamps, so
  // hand-written JSON does not trip it.
  test('a message whose text is JSON is not mistaken for an envelope', () => {
    expect(looksLikeCiphertextEnvelope('{"hello":1}')).toBe(false);
    expect(looksLikeCiphertextEnvelope('{"iv":"x","ct":"y"}')).toBe(false);
  });

  test('user JSON survives a round trip unchanged', async () => {
    for (const text of ['{"hello":1}', '{"iv":"x","ct":"y"}']) {
      const sealed = await encryptMessage(text, SECRET);
      expect(await decryptMessage(sealed, SECRET)).toBe(text);
    }
  });
});

describe('reading a plaintext row while encryption is on', () => {
  // The operator needs to know the row predates the toggle. AES-GCM's own
  // error cannot distinguish that from a damaged row or a wrong key.
  test('fails with an error naming the toggle, not a DOMException', async () => {
    expect(decryptMessage('written before encryption was enabled', SECRET)).rejects.toThrow(
      /FAM_ENCRYPT_MESSAGES/
    );
  });

  test('the error is not the raw crypto one', async () => {
    try {
      await decryptMessage('written before encryption was enabled', SECRET);
      throw new Error('should not have decrypted');
    } catch (e) {
      expect(String(e)).not.toMatch(/provided data is too small/);
    }
  });
});

describe('refusing to serve ciphertext as message text', () => {
  test('throws on a sealed row, naming which one', async () => {
    const sealed = await encryptMessage('secret', SECRET);
    expect(() =>
      assertNotSealed([
        { id: 1, text: 'a normal message' },
        { id: 2, text: sealed },
      ])
    ).toThrow(/Message 2/);
  });

  test('the error names the flag so an operator knows what to change', async () => {
    const sealed = await encryptMessage('secret', SECRET);
    expect(() => assertNotSealed([{ id: 7, text: sealed }])).toThrow(/FAM_ENCRYPT_MESSAGES/);
  });

  test('plaintext rows pass through untouched', () => {
    expect(() =>
      assertNotSealed([
        { id: 1, text: 'hello' },
        { id: 2, text: '{"hello":1}' },
      ])
    ).not.toThrow();
  });
});
