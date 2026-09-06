import { test, expect, describe } from 'bun:test';
import { accountKeyFingerprint, fingerprintsMatch } from '../fingerprint';
import { generateKeyPair, bufferToBase64 } from '../keys';

// ============================================================================
// ⚠️ THIS IS THE PIECE THAT MAKES AN ANCHOR CHECKABLE RATHER THAN MERELY
// RELAY-INDEPENDENT.
//
// `DESIGN-FEDERATION.md` has said, since it was written: "The anchor is
// currently REAL BUT NOT VERIFIABLE, which is a better position than today and
// still not a checkable one. A peer that fetches an account key from a repo has
// removed the RELAY from the trust path — but cannot tell that the key it holds
// CAME from there, nor notice when the answer changes. Closing that needs
// pinning-on-first-use with change alerts, a transparency log, or at minimum a
// fingerprint the holder publishes out of band. None is built."
//
// Pinning with change alerts shipped. This is the fingerprint, and it is what
// converts TRUST-on-first-use into VERIFIED-on-first-use: a peer who was told
// the fingerprint out of band can check that the key a forge served them is the
// one the holder meant.
//
// ⚠️ IT IS COMPUTED OVER THE RAW KEY BYTES, NEVER THE BASE64 TEXT. Two spellings
// of one key must not produce two fingerprints — a fingerprint that depends on
// encoding is one that fails exactly when someone re-encodes a key while moving
// it between systems, which is the moment they most need it to hold.
//
// ⚠️ AND IT IS A DIFFERENT CONCEPT FROM `keyIdFor` IN `message-encryption.ts`,
// which fingerprints the SERVER SECRET so a stored row can say which key sealed
// it. Same word, unrelated subject. Say which one.
// ============================================================================

async function aKey(): Promise<string> {
  return bufferToBase64((await generateKeyPair()).publicKey);
}

describe('the fingerprint identifies a key', () => {
  test('is deterministic for the same key', async () => {
    const key = await aKey();
    expect(await accountKeyFingerprint(key)).toBe(await accountKeyFingerprint(key));
  });

  test('⚠️ differs for different keys — the entire point', async () => {
    // A fingerprint that collided would let a substituted anchor pass the one
    // check that exists to catch it.
    const a = await accountKeyFingerprint(await aKey());
    const b = await accountKeyFingerprint(await aKey());
    expect(a).not.toBe(b);
  });

  test('survives a decode/re-encode round trip', async () => {
    // ⚠️ THIS TEST WAS NAMED "computed over the KEY BYTES, not the base64
    // spelling" AND DID NOT ESTABLISH THAT. A mutant that hashes the base64
    // TEXT instead of the decoded bytes SURVIVED it — because the two inputs
    // compared here are the SAME STRING, and hashing text or bytes gives the
    // same answer for identical input. The test asserted determinism and was
    // labelled with a stronger claim.
    //
    // ⚠️ AND THE MUTANT IS GENUINELY INERT, not a hole: `assertRaw32ByteKey`
    // round-trips the encoding, so a non-canonical spelling never reaches the
    // hash at all. Within the validated domain, text and bytes cannot diverge.
    //
    // So the property is real and it is HELD BY A NEIGHBOUR. If that validator
    // ever loosened to accept non-canonical base64, byte-hashing and
    // text-hashing would part company and nothing here would notice — which is
    // the coupling worth writing down rather than a check worth faking.
    const key = await aKey();
    const reEncoded = Buffer.from(key, 'base64').toString('base64');

    expect(reEncoded).toBe(key); // the encoding really is canonical
    expect(await accountKeyFingerprint(reEncoded)).toBe(await accountKeyFingerprint(key));
  });
});

describe('the format is meant to be compared by a person', () => {
  test('is grouped, fixed-length, and unambiguous to read aloud', async () => {
    const fp = await accountKeyFingerprint(await aKey());

    // Groups of 4 hex separated by '-'. Hex rather than base64 or base32
    // because a person reads this to another person: no I/l or O/0 confusion,
    // and no new encoder to get wrong.
    expect(fp).toMatch(/^[0-9a-f]{4}(-[0-9a-f]{4}){7}$/);
  });

  test('carries 128 bits, which is what makes grinding a match infeasible', async () => {
    // 32 hex characters = 128 bits. Short enough to read over a phone, long
    // enough that an attacker cannot search for a key whose fingerprint
    // matches the one a holder published.
    const fp = await accountKeyFingerprint(await aKey());
    expect(fp.replace(/-/g, '')).toHaveLength(32);
  });
});

describe('⚠️ a key it cannot fingerprint', () => {
  test('is REFUSED, not fingerprinted anyway', async () => {
    // A fingerprint of a malformed key is a confident answer about nothing, and
    // it would be compared against a real one and reported as a mismatch —
    // sending someone to investigate a substitution when the real fault is a
    // truncated paste.
    await expect(accountKeyFingerprint('not-a-key')).rejects.toThrow();
  });

  test('an empty string is refused', async () => {
    await expect(accountKeyFingerprint('')).rejects.toThrow();
  });

  test('a base64 string of the WRONG LENGTH is refused', async () => {
    // 32 bytes is the only valid size. A 31- or 33-byte value is not a key, and
    // hashing it would produce something that looks exactly like a fingerprint.
    const tooShort = Buffer.alloc(31).toString('base64');
    await expect(accountKeyFingerprint(tooShort)).rejects.toThrow();
  });
});

describe('comparing a fingerprint a person was told', () => {
  test('case and separators are forgiven, because a person types this', async () => {
    const fp = await accountKeyFingerprint(await aKey());

    expect(fingerprintsMatch(fp.toUpperCase(), fp)).toBe(true);
    expect(fingerprintsMatch(fp.replace(/-/g, ''), fp)).toBe(true);
    expect(fingerprintsMatch(fp.replace(/-/g, ' '), fp)).toBe(true);
  });

  test('⚠️ a PREFIX does not match — the whole width is the security parameter', async () => {
    // Accepting a prefix would let an attacker grind a much shorter target.
    // This is asserted because the claim is made in a comment, and a comment is
    // not a check.
    const fp = await accountKeyFingerprint(await aKey());
    const prefix = fp.slice(0, 9); // "aaaa-bbbb"

    expect(fingerprintsMatch(prefix, fp)).toBe(false);
  });

  test('two different keys never match', async () => {
    const a = await accountKeyFingerprint(await aKey());
    const b = await accountKeyFingerprint(await aKey());
    expect(fingerprintsMatch(a, b)).toBe(false);
  });

  test('control: an identical string matches, so the comparator can say YES', async () => {
    // Without this, every assertion above passes against a function that always
    // returns false.
    const fp = await accountKeyFingerprint(await aKey());
    expect(fingerprintsMatch(fp, fp)).toBe(true);
  });
});
