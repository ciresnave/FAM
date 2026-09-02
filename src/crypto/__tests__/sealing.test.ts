import { test, expect, describe } from 'bun:test';
import { generateEncryptionKeyPair } from '../keys';

// ============================================================================
// End-to-end message sealing: confidentiality FROM THE RELAY, which is not what
// `message-encryption.ts` provides.
//
// That module encrypts at rest under a key derived from FAM_SERVER_SECRET, so
// the server reads every message. It protects a stolen disk. It is orthogonal
// to this and stays.
//
// WHY A SECOND KEYPAIR, measured rather than assumed (Bun 1.3.14):
//
//   X25519 generateKey / deriveBits / raw export      OK, 32 bytes, parties AGREE
//   Ed25519 public imported as X25519, empty usages   OK          <- the trap
//   deriveBits against that imported key              OK, 32 bytes <- still the trap
//   Ed25519 private imported as X25519                FAIL "does not meet requirements"
//
// Importing an Ed25519 public key as X25519 SUCCEEDS and deriving against it
// PRODUCES 32 PLAUSIBLE BYTES — but the key's owner cannot import their own
// private half, so they can never reproduce that secret. The shortcut yields
// ciphertext nobody can open, and every check short of testing AGREEMENT passes.
//
// A non-event producing a plausible number. So entity encryption keys are real
// X25519, generated separately, and the test below asserts agreement rather
// than the success of any single call.
// ============================================================================

describe('entity encryption keys are X25519, separate from the Ed25519 identity key', () => {
  test('two parties derive the same shared secret', async () => {
    const alice = await generateEncryptionKeyPair();
    const bob = await generateEncryptionKeyPair();

    const aliceView = await crypto.subtle.deriveBits(
      { name: 'X25519', public: await importPublic(bob.publicKey) },
      await importPrivate(alice.privateKey),
      256
    );
    const bobView = await crypto.subtle.deriveBits(
      { name: 'X25519', public: await importPublic(alice.publicKey) },
      await importPrivate(bob.privateKey),
      256
    );

    // AGREEMENT is the assertion. "deriveBits returned bytes" is the check that
    // the Ed25519 shortcut also passes.
    expect(Buffer.from(aliceView).equals(Buffer.from(bobView))).toBe(true);
    expect(new Uint8Array(aliceView).length).toBe(32);
  });

  test('a fresh pair does not agree with an unrelated one', async () => {
    // Negative control: if the assertion above passed for ANY two keys, it would
    // be measuring nothing.
    const alice = await generateEncryptionKeyPair();
    const bob = await generateEncryptionKeyPair();
    const mallory = await generateEncryptionKeyPair();

    const real = await crypto.subtle.deriveBits(
      { name: 'X25519', public: await importPublic(bob.publicKey) },
      await importPrivate(alice.privateKey),
      256
    );
    const wrong = await crypto.subtle.deriveBits(
      { name: 'X25519', public: await importPublic(mallory.publicKey) },
      await importPrivate(alice.privateKey),
      256
    );

    expect(Buffer.from(real).equals(Buffer.from(wrong))).toBe(false);
  });

  test('the public half is 32 raw bytes and the keys are not the identity keys', async () => {
    const a = await generateEncryptionKeyPair();
    const b = await generateEncryptionKeyPair();
    expect(a.publicKey.length).toBe(32);
    // Distinct material every time — a constant would satisfy the tests above.
    expect(Buffer.from(a.publicKey).equals(Buffer.from(b.publicKey))).toBe(false);
  });
});

async function importPublic(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', raw.buffer as ArrayBuffer, { name: 'X25519' }, false, []);
}
async function importPrivate(pkcs8: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'pkcs8',
    pkcs8.buffer as ArrayBuffer,
    { name: 'X25519' },
    false,
    ['deriveBits']
  );
}

// ============================================================================
// Sealing. Ephemeral-static ECDH (the sealed-box / ECIES shape): the SENDER
// makes a throwaway X25519 pair per message, derives against the recipient's
// long-term public key, and ships the ephemeral public key in the envelope.
//
// Two consequences worth stating, because both are the point:
//   - The sender needs no long-term encryption key at all — only the
//     recipient's public one. Nothing to distribute in the send direction.
//   - Sealing says NOTHING about who sent it. Authenticity is the Ed25519
//     signature, a separate half. Anyone holding a public key can seal to it,
//     and that is not a defect being tolerated, it is the division of labour.
// ============================================================================

import { seal, open } from '../sealing';

describe('sealing gives confidentiality from the relay', () => {
  test('the recipient recovers exactly what was sealed', async () => {
    const bob = await generateEncryptionKeyPair();
    const envelope = await seal(toB64(bob.publicKey), 'ship it on friday');

    expect(await open(toB64(bob.privateKey), envelope)).toBe('ship it on friday');
  });

  test('the plaintext does not appear in the envelope', async () => {
    // The assertion a round-trip alone cannot make: a seal that returned its
    // input unchanged would pass the test above.
    const bob = await generateEncryptionKeyPair();
    const envelope = await seal(toB64(bob.publicKey), 'ship it on friday');

    expect(JSON.stringify(envelope)).not.toContain('ship it on friday');
    expect(JSON.stringify(envelope)).not.toContain('friday');
  });

  test('a different key cannot open it', async () => {
    const bob = await generateEncryptionKeyPair();
    const mallory = await generateEncryptionKeyPair();
    const envelope = await seal(toB64(bob.publicKey), 'ship it on friday');

    await expect(open(toB64(mallory.privateKey), envelope)).rejects.toThrow();
  });

  test('a tampered ciphertext is refused rather than returned mangled', async () => {
    const bob = await generateEncryptionKeyPair();
    const envelope = await seal(toB64(bob.publicKey), 'ship it on friday');

    const flipped = { ...envelope, ciphertext: flipOneBit(envelope.ciphertext) };
    await expect(open(toB64(bob.privateKey), flipped)).rejects.toThrow();
  });

  test('sealing the same text twice produces different envelopes', async () => {
    // A fixed ephemeral key or a fixed IV would make two seals identical and
    // leak equality of plaintexts across messages.
    const bob = await generateEncryptionKeyPair();
    const a = await seal(toB64(bob.publicKey), 'same text');
    const b = await seal(toB64(bob.publicKey), 'same text');

    expect(a.ciphertext).not.toBe(b.ciphertext);
    expect(a.ephemeralPublicKey).not.toBe(b.ephemeralPublicKey);
    expect(await open(toB64(bob.privateKey), a)).toBe('same text');
    expect(await open(toB64(bob.privateKey), b)).toBe('same text');
  });

  test('an empty message seals and opens as an empty message', async () => {
    const bob = await generateEncryptionKeyPair();
    const envelope = await seal(toB64(bob.publicKey), '');
    expect(await open(toB64(bob.privateKey), envelope)).toBe('');
  });

  test('unicode survives the round trip byte for byte', async () => {
    const bob = await generateEncryptionKeyPair();
    const text = 'héllo — 🔐 とりあえず';
    expect(await open(toB64(bob.privateKey), await seal(toB64(bob.publicKey), text))).toBe(text);
  });
});

function toB64(b: Uint8Array): string {
  return Buffer.from(b).toString('base64');
}

function flipOneBit(b64: string): string {
  const bytes = new Uint8Array(Buffer.from(b64, 'base64'));
  bytes[0] ^= 0x01;
  return Buffer.from(bytes).toString('base64');
}

// ============================================================================
// The seam, tested directly — because the black-box suite above CANNOT reach it.
//
// Two mutants survived all ten tests above:
//
//   1. content key derived from 32 zero bytes instead of the ECDH secret
//   2. the public-key binding dropped from the HKDF salt and the GCM AAD
//
// Mutant 1 is a total break. Every remaining input to the KDF is public — the
// ephemeral key ships inside the envelope and the recipient's public key is
// public by definition — so anyone holding an envelope derives its key. And
// "a different key cannot open it" still passed, because the mutant's salt
// still contains the recipient's public key, so a different recipient still
// lands on a different key. THE TEST PASSED FOR A REASON UNRELATED TO THE
// PROPERTY IT NAMES.
//
// Mutant 2 survives symmetrically. Each is masked by the half the other keeps,
// which is why running them one at a time made both look covered.
//
// The distinguishing operation — derive a key from public inputs alone — is one
// seal/open never offers, so no test written against that pair can separate
// them. Hence these two, which hold one KDF input fixed and vary the other.
// ============================================================================

import { deriveShared, deriveContentKey } from '../sealing';

describe('both KDF inputs are load-bearing', () => {
  const binding = new Uint8Array(64).fill(7);

  test('a different shared secret gives a different key, binding held fixed', async () => {
    // KILLS MUTANT 1. If the ECDH secret is ignored, these two are the same key.
    const a = await deriveContentKey(bytes(32, 1), binding);
    const b = await deriveContentKey(bytes(32, 2), binding);

    expect(await probe(a)).not.toBe(await probe(b));
  });

  test('a different binding gives a different key, shared secret held fixed', async () => {
    // KILLS MUTANT 2. If the binding leaves the salt, these two are the same key.
    const secret = bytes(32, 3);
    const a = await deriveContentKey(secret, new Uint8Array(64).fill(7));
    const b = await deriveContentKey(secret, new Uint8Array(64).fill(9));

    expect(await probe(a)).not.toBe(await probe(b));
  });

  test('the same inputs give the same key', async () => {
    // Positive control. Without it the two tests above are satisfied by a
    // derivation that simply returns something new every call.
    const a = await deriveContentKey(bytes(32, 4), binding);
    const b = await deriveContentKey(bytes(32, 4), binding);

    expect(await probe(a)).toBe(await probe(b));
  });

  test('ECDH agrees in both directions and depends on the pair', async () => {
    const alice = await generateEncryptionKeyPair();
    const bob = await generateEncryptionKeyPair();
    const mallory = await generateEncryptionKeyPair();

    const ab = await deriveShared(await priv(alice.privateKey), await pub(bob.publicKey));
    const ba = await deriveShared(await priv(bob.privateKey), await pub(alice.publicKey));
    const am = await deriveShared(await priv(alice.privateKey), await pub(mallory.publicKey));

    expect(Buffer.from(ab).equals(Buffer.from(ba))).toBe(true);
    expect(Buffer.from(ab).equals(Buffer.from(am))).toBe(false);
  });
});

describe('envelope version', () => {
  test('an envelope from a future construction is refused, not misread', async () => {
    const bob = await generateEncryptionKeyPair();
    const envelope = await seal(toB64(bob.publicKey), 'hello');

    await expect(open(toB64(bob.privateKey), { ...envelope, version: 2 })).rejects.toThrow(
      /version 2/
    );
  });
});

/**
 * Compare two derived keys without extracting them.
 *
 * `deriveContentKey` returns a non-extractable CryptoKey by design, so equality
 * is observed rather than read: encrypt fixed plaintext under a fixed IV and
 * compare the ciphertext. Equal keys give equal output; different keys do not.
 * Safe here only because these are throwaway test keys — a fixed IV under a
 * reused real key is exactly the mistake this construction avoids.
 */
async function probe(key: CryptoKey): Promise<string> {
  const out = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: new Uint8Array(12) },
    key,
    new TextEncoder().encode('probe')
  );
  return Buffer.from(out).toString('base64');
}

function bytes(n: number, fill: number): ArrayBuffer {
  return new Uint8Array(n).fill(fill).buffer;
}
async function pub(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', raw.buffer as ArrayBuffer, { name: 'X25519' }, false, []);
}
async function priv(pkcs8: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'pkcs8',
    pkcs8.buffer as ArrayBuffer,
    { name: 'X25519' },
    false,
    ['deriveBits']
  );
}
