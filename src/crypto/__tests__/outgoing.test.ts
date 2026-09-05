import { test, expect, describe, beforeAll } from 'bun:test';
import { generateKeyPair, generateEncryptionKeyPair, bufferToBase64 } from '../keys';
import { open } from '../sealing';
import { verifyEnvelope } from '../envelope';
import { prepareSealedDirect } from '../outgoing';

// ============================================================================
// ⚠️ ONE PLACE DECIDES WHETHER AN OUTGOING MESSAGE IS SEALED.
//
// The CLI and the MCP adapter both send. If each decides for itself whether the
// recipient can receive sealed mail, that is two answers to one question, and
// they will drift — with the drift showing up as one adapter quietly sending
// plaintext where the other seals. So the decision, the envelope construction
// and the refusal all live in one function, and both adapters call it.
//
// ⚠️ THE FUNCTION NEVER PRODUCES A PLAINTEXT FALLBACK. It returns either a
// sealed envelope or a REFUSAL carrying a reason. A helper that returned
// "here is your message, unsealed" on the failure path would put the silent
// downgrade back exactly where this increment removed it — and the caller that
// forgot to check the flag is the one that ships it.
// ============================================================================

let sender: { publicKey: Uint8Array; privateKey: Uint8Array };
let recipientEnc: { publicKey: Uint8Array; privateKey: Uint8Array };

const SENDER_ID = 'alice@example.com';
const RECIPIENT_ID = 'bob@example.com';

beforeAll(async () => {
  sender = await generateKeyPair();
  recipientEnc = await generateEncryptionKeyPair();
});

function baseInput(over: Record<string, unknown> = {}) {
  return {
    senderId: SENDER_ID,
    senderIdentityPrivateKey: bufferToBase64(sender.privateKey),
    recipientId: RECIPIENT_ID,
    recipientEncryptionPublicKey: bufferToBase64(recipientEnc.publicKey),
    text: 'the quick brown fox',
    sequence: 1,
    ...over,
  };
}

describe('a recipient who can receive sealed mail', () => {
  test('the envelope opens with the recipient private half, and only that', async () => {
    const decision = await prepareSealedDirect(baseInput());

    expect(decision.sealed).toBe(true);
    if (!decision.sealed) throw new Error('unreachable');

    expect(await open(bufferToBase64(recipientEnc.privateKey), decision.envelope.sealed)).toBe(
      'the quick brown fox'
    );
  });

  test('the signature verifies against the sender identity key', async () => {
    const decision = await prepareSealedDirect(baseInput());
    if (!decision.sealed) throw new Error('expected sealed');

    expect(
      await verifyEnvelope(bufferToBase64(sender.publicKey), decision.envelope)
    ).toBe(true);
  });

  test('⚠️ the plaintext does not appear anywhere in the envelope', async () => {
    // The assertion that catches the failure the type system cannot: an
    // envelope that carries the sealed body AND the original text alongside it.
    // Every other test here would still pass — the seal opens, the signature
    // verifies — while the relay reads the message off the wire.
    const decision = await prepareSealedDirect(baseInput({ text: 'SENTINEL-PLAINTEXT-9f3a' }));
    if (!decision.sealed) throw new Error('expected sealed');

    expect(JSON.stringify(decision.envelope)).not.toContain('SENTINEL-PLAINTEXT-9f3a');
  });

  test('sender and recipient are bound to the ids given, not to anything else', async () => {
    const decision = await prepareSealedDirect(baseInput());
    if (!decision.sealed) throw new Error('expected sealed');

    expect(decision.envelope.sender).toBe(SENDER_ID);
    expect(decision.envelope.recipient).toBe(RECIPIENT_ID);
  });
});

describe('a recipient who cannot', () => {
  test('⚠️ a missing key is a REFUSAL, never a plaintext fallback', async () => {
    const decision = await prepareSealedDirect(
      baseInput({ recipientEncryptionPublicKey: null })
    );

    expect(decision.sealed).toBe(false);
    if (decision.sealed) throw new Error('expected refusal');

    // The reason has to name the recipient and a remedy, because the caller
    // shows it to a person who then has to do something about it.
    expect(decision.reason).toContain(RECIPIENT_ID);
    expect(decision.reason).toMatch(/publish|encryption key/i);
  });

  test('⚠️ an EMPTY STRING key is treated as no key, not as a key', async () => {
    // The null-vs-empty hazard, at the one place it would do the most damage.
    // '' is falsy, so a truthiness check happens to be right — but a length
    // check, a `!= null`, or a `typeof === 'string'` would all let '' through
    // to `seal()`, which would either throw deep in WebCrypto or, worse,
    // produce an envelope nobody can open.
    const decision = await prepareSealedDirect(
      baseInput({ recipientEncryptionPublicKey: '' })
    );

    expect(decision.sealed).toBe(false);
  });

  test('the refusal does not carry the message text', async () => {
    // A refusal that echoed the text would put the plaintext into a log line
    // or an error report, which is a disclosure the sealed path exists to
    // prevent.
    const decision = await prepareSealedDirect(
      baseInput({ recipientEncryptionPublicKey: null, text: 'SENTINEL-REFUSAL-4b81' })
    );

    expect(JSON.stringify(decision)).not.toContain('SENTINEL-REFUSAL-4b81');
  });
});
