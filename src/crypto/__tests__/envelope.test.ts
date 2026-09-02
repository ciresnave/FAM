import { test, expect, describe } from 'bun:test';
import { generateKeyPair, generateEncryptionKeyPair, bufferToBase64 } from '../keys';
import { seal } from '../sealing';
import { canonicalBytes, signEnvelope, verifyEnvelope, openSigned } from '../envelope';
import type { EnvelopeFields } from '../envelope';

// ============================================================================
// The authenticity half.
//
// `sealing.ts` gives confidentiality and says NOTHING about who sent a message
// — anyone holding a public key can seal to it. This module signs the sealed
// envelope with the sender's Ed25519 identity key, which is the half that makes
// a message attributable without trusting the relay that carried it.
//
// The two stay separate on purpose. A reader who takes "encrypted" to mean
// "authentic" gets neither.
// ============================================================================

const SEALED_STUB = {
  version: 1,
  ephemeralPublicKey: 'ZXBo',
  iv: 'aXY=',
  ciphertext: 'Y3Q=',
};

function fields(over: Partial<EnvelopeFields> = {}): EnvelopeFields {
  return {
    sender: 'alice@acme.test',
    recipient: 'bob@acme.test',
    sentAt: '2026-09-02T14:00:00.000Z',
    sequence: 1,
    sealed: SEALED_STUB,
    ...over,
  };
}

describe('a signed envelope is attributable without trusting the relay', () => {
  test('it verifies under the sender key', async () => {
    const alice = await generateKeyPair();
    const envelope = await signEnvelope(bufferToBase64(alice.privateKey), fields());

    expect(await verifyEnvelope(bufferToBase64(alice.publicKey), envelope)).toBe(true);
  });

  test('it does not verify under a different key', async () => {
    const alice = await generateKeyPair();
    const mallory = await generateKeyPair();
    const envelope = await signEnvelope(bufferToBase64(alice.privateKey), fields());

    expect(await verifyEnvelope(bufferToBase64(mallory.publicKey), envelope)).toBe(false);
  });
});

describe('every field the envelope asserts is covered by the signature', () => {
  // One test per field rather than one test over an object. A loop that mutated
  // "some field" would pass while leaving a specific field uncovered, and the
  // uncovered one is the whole risk: a relay that can change the recipient or
  // replay a sequence number without breaking the signature is a relay that is
  // still trusted.
  const mutations: Array<[string, Partial<EnvelopeFields>]> = [
    ['sender', { sender: 'mallory@acme.test' }],
    ['recipient', { recipient: 'carol@acme.test' }],
    ['sentAt', { sentAt: '2026-09-02T15:00:00.000Z' }],
    ['sequence', { sequence: 2 }],
    ['sealed.ciphertext', { sealed: { ...SEALED_STUB, ciphertext: 'b3RoZXI=' } }],
    ['sealed.iv', { sealed: { ...SEALED_STUB, iv: 'b3Ro' } }],
    ['sealed.ephemeralPublicKey', { sealed: { ...SEALED_STUB, ephemeralPublicKey: 'b3Ro' } }],
  ];

  for (const [name, mutation] of mutations) {
    test(`changing ${name} breaks verification`, async () => {
      const alice = await generateKeyPair();
      const envelope = await signEnvelope(bufferToBase64(alice.privateKey), fields());
      const tampered = { ...envelope, ...mutation };

      expect(await verifyEnvelope(bufferToBase64(alice.publicKey), tampered)).toBe(false);
    });
  }
});

describe('field boundaries are unambiguous', () => {
  // ⚠️ THE DEFECT THIS EXISTS TO PREVENT, and it is invisible to every test
  // above. If the signed bytes are fields joined without their lengths, then
  //
  //     sender "ab@x"  recipient "c@y"
  //     sender "ab@xc" recipient "@y"
  //
  // serialise identically, so ONE signature is valid for BOTH. A relay swaps
  // the split and the message is attributed to a different sender, or delivered
  // to a different recipient, with the signature still checking out.
  //
  // Nothing in a round-trip test can see this. Both envelopes verify correctly
  // against their own contents; the defect is that they are not their own.
  test('two different splits of the same characters sign differently', () => {
    const a = canonicalBytes({ version: 1, ...fields({ sender: 'ab@x', recipient: 'c@y' }) });
    const b = canonicalBytes({ version: 1, ...fields({ sender: 'ab@xc', recipient: '@y' }) });

    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });

  test('a signature does not carry across such a split', async () => {
    // The same property stated where it bites, so the guarantee is not only a
    // fact about the encoder.
    const alice = await generateKeyPair();
    const signed = await signEnvelope(
      bufferToBase64(alice.privateKey),
      fields({ sender: 'ab@x', recipient: 'c@y' })
    );
    const respliced = { ...signed, sender: 'ab@xc', recipient: '@y' };

    expect(await verifyEnvelope(bufferToBase64(alice.publicKey), respliced)).toBe(false);
  });

  test('identical fields encode identically', () => {
    // Positive control. The two tests above are satisfied by an encoder that
    // returns something different every call, which would break verification.
    expect(
      Buffer.from(canonicalBytes({ version: 1, ...fields() })).equals(
        Buffer.from(canonicalBytes({ version: 1, ...fields() }))
      )
    ).toBe(true);
  });
});

describe('opening a signed envelope checks the signature FIRST', () => {
  test('a well-formed envelope round trips', async () => {
    const alice = await generateKeyPair();
    const bob = await generateEncryptionKeyPair();

    const sealed = await seal(bufferToBase64(bob.publicKey), 'the numbers are in');
    const envelope = await signEnvelope(bufferToBase64(alice.privateKey), fields({ sealed }));

    const text = await openSigned(
      bufferToBase64(alice.publicKey),
      bufferToBase64(bob.privateKey),
      envelope
    );
    expect(text).toBe('the numbers are in');
  });

  test('an envelope signed by someone else is refused', async () => {
    const alice = await generateKeyPair();
    const mallory = await generateKeyPair();
    const bob = await generateEncryptionKeyPair();

    const sealed = await seal(bufferToBase64(bob.publicKey), 'the numbers are in');
    // Signed by Mallory, presented as Alice's.
    const envelope = await signEnvelope(bufferToBase64(mallory.privateKey), fields({ sealed }));

    await expect(
      openSigned(bufferToBase64(alice.publicKey), bufferToBase64(bob.privateKey), envelope)
    ).rejects.toThrow(/signature/i);
  });

  test('the signature is checked BEFORE the ciphertext is touched', async () => {
    // The test above was originally named "...and the ciphertext is never
    // decrypted", which it did not check: a decrypt-then-verify implementation
    // rejects it too, just later. The name claimed an ordering the assertion
    // could not see.
    //
    // This one discriminates. The envelope is bad in BOTH ways at once — a
    // signature that will not verify AND a sealed body that cannot be opened —
    // so the error names whichever check ran first.
    const alice = await generateKeyPair();
    const bob = await generateEncryptionKeyPair();

    const unopenable = {
      version: 1,
      ephemeralPublicKey: Buffer.alloc(32).toString('base64'),
      iv: Buffer.alloc(12).toString('base64'),
      ciphertext: Buffer.from('not a valid gcm ciphertext').toString('base64'),
    };
    const forged = { version: 1, ...fields({ sealed: unopenable }), signature: 'AAAA' };

    // Verify first  -> SIGNATURE_INVALID.
    // Decrypt first -> SEALED_MESSAGE_UNOPENABLE, and an unauthenticated
    //                  ciphertext would have reached the crypto path.
    await expect(
      openSigned(bufferToBase64(alice.publicKey), bufferToBase64(bob.privateKey), forged)
    ).rejects.toThrow(/signature/i);
  });

  test('an unsigned-but-openable envelope is still refused', async () => {
    // Decryption succeeding is not authentication. Anyone holding Bob's public
    // key can produce ciphertext Bob can open; only the signature says who did.
    const alice = await generateKeyPair();
    const bob = await generateEncryptionKeyPair();

    const sealed = await seal(bufferToBase64(bob.publicKey), 'from nobody in particular');
    const forged = { version: 1, ...fields({ sealed }), signature: 'AAAA' };

    await expect(
      openSigned(bufferToBase64(alice.publicKey), bufferToBase64(bob.privateKey), forged)
    ).rejects.toThrow(/signature/i);
  });
});
