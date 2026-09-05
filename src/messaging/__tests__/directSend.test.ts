import { test, expect, describe, beforeAll } from 'bun:test';
import { generateKeyPair, generateEncryptionKeyPair, bufferToBase64 } from '../../crypto/keys';
import { open } from '../../crypto/sealing';
import { sendDirectVia, type DirectSendTransport } from '../directSend';

// ============================================================================
// ⚠️ THE POLICY IS SHARED; ONLY THE TRANSPORT DIFFERS.
//
// The CLI and the MCP adapter both send direct messages. `prepareSealedDirect`
// already stops them answering "can this be sealed?" differently — but the
// REST of the policy is just as capable of drifting: whether a refusal is fatal,
// whether an invisible recipient counts as keyless, and whether anything is
// posted before the refusal. Those are decisions, not plumbing, and duplicating
// them into a second adapter is how one of them ends up sending plaintext where
// the other refuses.
//
// So the policy takes a transport and both adapters supply one. The fake below
// makes the assertion that matters directly observable: NOT MERELY THAT IT
// THREW, BUT THAT NOTHING WAS SENT. A refusal raised after the post satisfies
// `rejects.toThrow` while the plaintext is already gone.
// ============================================================================

let sender: { publicKey: Uint8Array; privateKey: Uint8Array };
let recipientEnc: { publicKey: Uint8Array; privateKey: Uint8Array };

const SENDER_ID = 'alice@example.com';
const RECIPIENT_ID = 'bob@example.com';

interface Recorder {
  transport: DirectSendTransport;
  sealedCalls: number;
  plaintextCalls: number;
  lastSealedRecipient: string | null;
  lastEnvelope: any;
}

function recordingTransport(
  visible: Array<{ id: string; encryption_public_key: string | null }>
): Recorder {
  const rec: Recorder = {
    sealedCalls: 0,
    plaintextCalls: 0,
    lastSealedRecipient: null,
    lastEnvelope: null,
    transport: null as any,
  };

  rec.transport = {
    async listVisibleEntities() {
      return visible;
    },
    async sendSealed(recipientId, envelope) {
      rec.sealedCalls += 1;
      rec.lastSealedRecipient = recipientId;
      rec.lastEnvelope = envelope;
      return { messageId: 101, response: { delivery: 'pushed' } };
    },
    async sendPlaintext(_recipientId, _text) {
      rec.plaintextCalls += 1;
      return { messageId: 202 };
    },
  };

  return rec;
}

beforeAll(async () => {
  sender = await generateKeyPair();
  recipientEnc = await generateEncryptionKeyPair();
});

function input(over: Record<string, unknown> = {}) {
  return {
    senderId: SENDER_ID,
    senderIdentityPrivateKey: bufferToBase64(sender.privateKey),
    recipientId: RECIPIENT_ID,
    text: 'hello',
    ...over,
  } as any;
}

function withKey() {
  return [{ id: RECIPIENT_ID, encryption_public_key: bufferToBase64(recipientEnc.publicKey) }];
}

function withoutKey() {
  return [{ id: RECIPIENT_ID, encryption_public_key: null }];
}

describe('a recipient who has published a key', () => {
  test('goes down the sealed path and never the plaintext one', async () => {
    const rec = recordingTransport(withKey());
    const outcome = await sendDirectVia(rec.transport, input());

    expect(outcome.sealed).toBe(true);
    expect(outcome.messageId).toBe(101);
    expect(rec.sealedCalls).toBe(1);
    expect(rec.plaintextCalls).toBe(0);
  });

  test('what reaches the transport actually opens for the recipient', async () => {
    // The transport is fake; the crypto is not. This is what stops the policy
    // "working" while handing the transport something unopenable.
    const rec = recordingTransport(withKey());
    await sendDirectVia(rec.transport, input({ text: 'through the seam' }));

    expect(rec.lastSealedRecipient).toBe(RECIPIENT_ID);
    expect(await open(bufferToBase64(recipientEnc.privateKey), rec.lastEnvelope.sealed)).toBe(
      'through the seam'
    );
  });
});

describe('a recipient with no key', () => {
  test('⚠️ refuses AND POSTS NOTHING', async () => {
    const rec = recordingTransport(withoutKey());

    await expect(sendDirectVia(rec.transport, input())).rejects.toThrow(/encryption key/i);

    // The load-bearing half. `rejects.toThrow` alone is satisfied by a refusal
    // raised after the message has already gone.
    expect(rec.sealedCalls).toBe(0);
    expect(rec.plaintextCalls).toBe(0);
  });

  test('sends unsealed only when explicitly allowed, and reports the downgrade', async () => {
    const rec = recordingTransport(withoutKey());
    const outcome = await sendDirectVia(rec.transport, input({ allowPlaintext: true }));

    expect(outcome.sealed).toBe(false);
    expect(outcome.messageId).toBe(202);
    expect(outcome.downgradeReason).toContain(RECIPIENT_ID);
    expect(rec.plaintextCalls).toBe(1);
    expect(rec.sealedCalls).toBe(0);
  });
});

describe('a recipient the sender cannot see', () => {
  test('⚠️ is an error even with plaintext allowed, and posts nothing', async () => {
    // "Not visible" is not "has no key". Collapsing them turns a visibility or
    // lookup failure into a plaintext send — to a recipient who may well have
    // published a key, for a reason that has nothing to do with them.
    const rec = recordingTransport([{ id: 'someone-else@x.com', encryption_public_key: null }]);

    await expect(
      sendDirectVia(rec.transport, input({ allowPlaintext: true }))
    ).rejects.toThrow(/not visible/i);

    expect(rec.sealedCalls).toBe(0);
    expect(rec.plaintextCalls).toBe(0);
  });

  test('control: the same directory WITH the recipient present seals fine', async () => {
    // Positive control for the test above — it fails for absence, not because
    // every directory is rejected.
    const rec = recordingTransport([
      { id: 'someone-else@x.com', encryption_public_key: null },
      ...withKey(),
    ]);

    const outcome = await sendDirectVia(rec.transport, input());
    expect(outcome.sealed).toBe(true);
  });
});
