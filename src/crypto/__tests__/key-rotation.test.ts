import { test, expect, describe } from 'bun:test';
import {
  encryptMessage,
  decryptMessage,
  keyIdFor,
  type Keyring,
} from '../message-encryption';

// ============================================================================
// Server-secret rotation
//
// The ciphertext envelope recorded no key identity, so a stored message could
// not say which secret encrypted it. That is why rotating FAM_SERVER_SECRET was
// documented as "don't" — a prohibition standing in for an unhandled case.
//
// Rotation is the moment "the same server" and "the same key" stop being
// synonyms, so a message has to carry which key it was sealed with.
// ============================================================================

const OLD = 'old-server-secret-aaaaaaaaaaaaaaaaaaaaaa';
const NEW = 'new-server-secret-bbbbbbbbbbbbbbbbbbbbbb';

describe('key identity', () => {
  test('a key id is stable for the same secret', async () => {
    expect(await keyIdFor(OLD)).toBe(await keyIdFor(OLD));
  });

  test('different secrets get different key ids', async () => {
    expect(await keyIdFor(OLD)).not.toBe(await keyIdFor(NEW));
  });

  // A key id travels in plaintext beside the ciphertext, so it must not be a
  // shortcut to the secret.
  test('a key id does not disclose the secret', async () => {
    const kid = await keyIdFor(OLD);
    expect(kid).not.toContain(OLD);
    expect(OLD).not.toContain(kid);
    expect(kid.length).toBeLessThan(OLD.length);
  });

  test('ciphertext records which key sealed it', async () => {
    const sealed = await encryptMessage('hello', OLD);
    const envelope = JSON.parse(sealed);
    expect(envelope.kid).toBe(await keyIdFor(OLD));
  });
});

describe('rotation', () => {
  // THE CASE THE PROHIBITION EXISTED FOR: a message sealed before rotation
  // must still be readable after it.
  test('a message sealed with the old secret survives rotation', async () => {
    const sealed = await encryptMessage('written before rotation', OLD);

    const rotated: Keyring = { current: NEW, previous: [OLD] };
    expect(await decryptMessage(sealed, rotated)).toBe('written before rotation');
  });

  test('new messages are sealed with the new key after rotation', async () => {
    const rotated: Keyring = { current: NEW, previous: [OLD] };
    const sealed = await encryptMessage('written after rotation', rotated);

    expect(JSON.parse(sealed).kid).toBe(await keyIdFor(NEW));
    expect(await decryptMessage(sealed, rotated)).toBe('written after rotation');
  });

  test('several generations back still decrypt', async () => {
    const OLDEST = 'oldest-secret-cccccccccccccccccccccccc';
    const sealed = await encryptMessage('ancient', OLDEST);

    const keyring: Keyring = { current: NEW, previous: [OLD, OLDEST] };
    expect(await decryptMessage(sealed, keyring)).toBe('ancient');
  });

  // Dropping a retired secret from the keyring is how data becomes
  // unreadable. It must say so, not surface as a generic crypto error.
  test('an unknown key id fails with a message naming the problem', async () => {
    const sealed = await encryptMessage('orphaned', OLD);
    const keyring: Keyring = { current: NEW, previous: [] };

    expect(decryptMessage(sealed, keyring)).rejects.toThrow(/key/i);
  });

  test('a bare secret still works and means "no previous keys"', async () => {
    const sealed = await encryptMessage('plain usage', OLD);
    expect(await decryptMessage(sealed, OLD)).toBe('plain usage');
  });
});

describe('backwards compatibility', () => {
  // Envelopes written before kid existed carry no key identity. They predate
  // rotation by definition, so the current secret is the only candidate.
  test('a pre-rotation envelope with no kid decrypts with the current secret', async () => {
    const sealed = await encryptMessage('legacy envelope', OLD);
    const envelope = JSON.parse(sealed);
    delete envelope.kid;

    expect(await decryptMessage(JSON.stringify(envelope), OLD)).toBe('legacy envelope');
  });

  test('rotation does not change round-tripping under a single secret', async () => {
    const sealed = await encryptMessage('unchanged behaviour', NEW);
    expect(await decryptMessage(sealed, NEW)).toBe('unchanged behaviour');
  });
});
