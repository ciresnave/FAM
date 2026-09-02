import { test, expect, describe } from 'bun:test';
import { generateEncryptionKeyPair, bufferToBase64 } from '../keys';
import { sealToMany, openGroup, type SealedGroupEnvelope } from '../groupSealing';

// ============================================================================
// Sealing one message to many recipients.
//
// ⚠️ THE BODY IS ENCRYPTED ONCE, UNDER A FRESH CONTENT KEY, AND ONLY THAT KEY
// IS WRAPPED PER RECIPIENT. The obvious alternative — seal the plaintext
// separately to each recipient — is wrong for a reason that is not about
// storage: N independent ciphertexts of the same plaintext is a different
// construction with a larger attack surface, and it makes "everyone got the
// same message" unverifiable. One ciphertext means one message by construction.
//
// WHAT THIS DOES NOT HIDE, stated so it is a decision rather than a discovery:
// the recipient list travels in the clear. Anyone holding the envelope learns
// who else can open it. For a channel that is not new information — the server
// already fans out per-recipient delivery rows from membership it must know to
// route at all, and members already know the membership. It WOULD be new
// information if this were ever used for an ad-hoc recipient set, so that is
// the case to think again about.
// ============================================================================

async function party() {
  const keys = await generateEncryptionKeyPair();
  return {
    publicKey: bufferToBase64(keys.publicKey),
    privateKey: bufferToBase64(keys.privateKey),
  };
}

describe('one message, many recipients', () => {
  test('every listed recipient opens the same plaintext', async () => {
    const [alice, bob, carol] = [await party(), await party(), await party()];

    const envelope = await sealToMany(
      [
        { entity: 'alice@x', publicKey: alice.publicKey },
        { entity: 'bob@x', publicKey: bob.publicKey },
        { entity: 'carol@x', publicKey: carol.publicKey },
      ],
      'ship it on friday'
    );

    expect(await openGroup('alice@x', alice.privateKey, envelope)).toBe('ship it on friday');
    expect(await openGroup('bob@x', bob.privateKey, envelope)).toBe('ship it on friday');
    expect(await openGroup('carol@x', carol.privateKey, envelope)).toBe('ship it on friday');
  });

  test('the body is encrypted ONCE and only the key is per-recipient', async () => {
    // The structural claim, asserted rather than assumed. A per-recipient
    // ciphertext would satisfy every round-trip test above.
    const [alice, bob, carol] = [await party(), await party(), await party()];

    const envelope = await sealToMany(
      [
        { entity: 'alice@x', publicKey: alice.publicKey },
        { entity: 'bob@x', publicKey: bob.publicKey },
        { entity: 'carol@x', publicKey: carol.publicKey },
      ],
      'one body'
    );

    expect(envelope.recipients.length).toBe(3);
    expect(typeof envelope.ciphertext).toBe('string');
    // Each recipient carries a wrapped key and nothing resembling a body.
    for (const r of envelope.recipients) {
      expect(r.wrappedKey.length).toBeGreaterThan(0);
      expect(r).not.toHaveProperty('ciphertext');
    }
  });

  test('the plaintext appears nowhere in the envelope', async () => {
    const alice = await party();
    const envelope = await sealToMany(
      [{ entity: 'alice@x', publicKey: alice.publicKey }],
      'ship it on friday'
    );
    expect(JSON.stringify(envelope)).not.toContain('friday');
  });

  test('a key that was not a recipient cannot open it', async () => {
    const [alice, mallory] = [await party(), await party()];
    const envelope = await sealToMany(
      [{ entity: 'alice@x', publicKey: alice.publicKey }],
      'members only'
    );

    // Not listed at all.
    await expect(openGroup('mallory@x', mallory.privateKey, envelope)).rejects.toThrow();
  });

  test('a listed recipient presenting the WRONG key cannot open it', async () => {
    // Distinct from the test above: here the entity IS in the list, so the
    // lookup succeeds and only the cryptography can refuse. Without this, the
    // recipient lookup alone would satisfy "outsiders are refused".
    const [alice, mallory] = [await party(), await party()];
    const envelope = await sealToMany(
      [{ entity: 'alice@x', publicKey: alice.publicKey }],
      'members only'
    );

    await expect(openGroup('alice@x', mallory.privateKey, envelope)).rejects.toThrow();
  });

  test('sealing the same text twice produces different envelopes', async () => {
    const alice = await party();
    const a = await sealToMany([{ entity: 'alice@x', publicKey: alice.publicKey }], 'same');
    const b = await sealToMany([{ entity: 'alice@x', publicKey: alice.publicKey }], 'same');

    expect(a.ciphertext).not.toBe(b.ciphertext);
    expect(await openGroup('alice@x', alice.privateKey, a)).toBe('same');
    expect(await openGroup('alice@x', alice.privateKey, b)).toBe('same');
  });

  test('the content key is FRESH PER MESSAGE, not shared across messages', async () => {
    // ⚠️ THIS TEST EXISTS BECAUSE A MUTANT SURVIVED, AND THE MUTANT WAS A TOTAL
    // BREAK. Replacing the random content key with a constant — so every message
    // in the system is encrypted under the same key, and one compromise reads
    // all of them — left ALL ELEVEN tests passing.
    //
    // "Sealing the same text twice produces different envelopes" does not catch
    // it: the body IV is still random, so the ciphertexts still differ. Every
    // round trip still works. Nothing about a single envelope can see it,
    // because the defect is a relationship BETWEEN envelopes.
    //
    // So the test builds the case where the two candidate behaviours give
    // different answers: take A's wrapped keys and B's body. Under a per-message
    // key that hybrid is unopenable — A's key does not fit B's body. Under a
    // shared key it opens B's plaintext, and the assertion below fails.
    //
    // Same shape as the KDF seam in sealing.ts: the distinguishing operation is
    // one the ordinary API never performs, so it has to be constructed.
    const alice = await party();
    const a = await sealToMany([{ entity: 'alice@x', publicKey: alice.publicKey }], 'message A');
    const b = await sealToMany([{ entity: 'alice@x', publicKey: alice.publicKey }], 'message B');

    const hybrid: SealedGroupEnvelope = {
      ...b, // B's iv and ciphertext
      recipients: a.recipients, // A's content key
    };

    await expect(openGroup('alice@x', alice.privateKey, hybrid)).rejects.toThrow();

    // Positive control: both envelopes are individually fine, so the rejection
    // above is about the MISMATCH and not about either envelope being broken.
    expect(await openGroup('alice@x', alice.privateKey, a)).toBe('message A');
    expect(await openGroup('alice@x', alice.privateKey, b)).toBe('message B');
  });

  test('a tampered body is refused for every recipient', async () => {
    const [alice, bob] = [await party(), await party()];
    const envelope = await sealToMany(
      [
        { entity: 'alice@x', publicKey: alice.publicKey },
        { entity: 'bob@x', publicKey: bob.publicKey },
      ],
      'original'
    );

    const flipped = { ...envelope, ciphertext: flipOneBit(envelope.ciphertext) };
    await expect(openGroup('alice@x', alice.privateKey, flipped)).rejects.toThrow();
    await expect(openGroup('bob@x', bob.privateKey, flipped)).rejects.toThrow();
  });

  test('tampering with ONE wrapped key affects only that recipient', async () => {
    // The property that makes per-recipient wrapping worth having: the
    // recipients are independent. If breaking one broke all, the wrapping would
    // be doing nothing the single-recipient seal does not.
    const [alice, bob] = [await party(), await party()];
    const envelope = await sealToMany(
      [
        { entity: 'alice@x', publicKey: alice.publicKey },
        { entity: 'bob@x', publicKey: bob.publicKey },
      ],
      'still fine for bob'
    );

    const damaged: SealedGroupEnvelope = {
      ...envelope,
      recipients: envelope.recipients.map((r) =>
        r.entity === 'alice@x' ? { ...r, wrappedKey: flipOneBit(r.wrappedKey) } : r
      ),
    };

    await expect(openGroup('alice@x', alice.privateKey, damaged)).rejects.toThrow();
    expect(await openGroup('bob@x', bob.privateKey, damaged)).toBe('still fine for bob');
  });
});

describe('refusals that prevent a message nobody can read', () => {
  test('an empty recipient list is refused', async () => {
    // A sealed message with no recipients is not a message. Producing one
    // silently would store ciphertext that can never be opened, and nothing
    // downstream would notice until someone tried to read it.
    await expect(sealToMany([], 'to nobody')).rejects.toThrow(/recipient/i);
  });

  test('a duplicate recipient is refused rather than silently deduplicated', async () => {
    // Deduplicating hides a caller bug. Two entries for one entity means the
    // caller built its list wrong, and the second wrap would be unreachable
    // anyway because lookup takes the first.
    const alice = await party();
    await expect(
      sealToMany(
        [
          { entity: 'alice@x', publicKey: alice.publicKey },
          { entity: 'alice@x', publicKey: alice.publicKey },
        ],
        'twice'
      )
    ).rejects.toThrow(/duplicate/i);
  });

  test('a recipient with a malformed key is refused, and nothing is produced', async () => {
    // Refused as a whole rather than sealed to the recipients that did work.
    // A partial group envelope is the "half-succeeded" shape: the caller sees
    // an error and some members silently never receive the message.
    const alice = await party();
    await expect(
      sealToMany(
        [
          { entity: 'alice@x', publicKey: alice.publicKey },
          { entity: 'bob@x', publicKey: 'not-a-key' },
        ],
        'partial'
      )
    ).rejects.toThrow();
  });
});

function flipOneBit(b64: string): string {
  const bytes = new Uint8Array(Buffer.from(b64, 'base64'));
  bytes[0] ^= 0x01;
  return Buffer.from(bytes).toString('base64');
}
