import { test, expect, describe, beforeAll } from 'bun:test';
import { generateKeyPair, generateEncryptionKeyPair, bufferToBase64 } from '../../crypto/keys';
import { openGroup } from '../../crypto/groupSealing';
import { verifyGroupEnvelope } from '../../crypto/envelope';
import { sendChannelVia, type ChannelSendTransport } from '../channelSend';

// ============================================================================
// ⚠️ A CHANNEL DOWNGRADE IS EVERY MEMBER'S DOWNGRADE.
//
// The direct path can fall back for one recipient. A channel cannot: the
// server requires the envelope's recipient set to equal the membership exactly,
// and refuses a partial one, because sealing to the members who happen to have
// keys leaves the rest holding a message they can never open while the sender
// sees success.
//
// So the client's question is all-or-nothing — can EVERY member receive sealed
// mail? — and when the answer is no, the refusal has to NAME who, because the
// sender cannot fix it and the people who can are the ones not named otherwise.
//
// ⚠️ AND THE SENDER IS A RECIPIENT OF THEIR OWN MESSAGE. They are a member, the
// server compares against membership, and a sender left out of their own
// envelope both fails that check and cannot read their own history. It is the
// one recipient it is natural to forget, so it is asserted directly.
// ============================================================================

const CHANNEL = 'chan-1';
const SENDER = 'alice@example.com';
const MEMBER = 'bob@example.com';
const KEYLESS = 'carol@example.com';

let senderIdentity: { publicKey: Uint8Array; privateKey: Uint8Array };
let senderEnc: { publicKey: Uint8Array; privateKey: Uint8Array };
let memberEnc: { publicKey: Uint8Array; privateKey: Uint8Array };

interface Recorder {
  transport: ChannelSendTransport;
  sealedCalls: number;
  plaintextCalls: number;
  lastEnvelope: any;
}

function recording(members: Array<{ id: string; encryption_public_key: string | null }>): Recorder {
  const rec: Recorder = {
    sealedCalls: 0,
    plaintextCalls: 0,
    lastEnvelope: null,
    transport: null as any,
  };
  rec.transport = {
    async listChannelMembers() {
      return members;
    },
    async sendSealedChannel(_channelId, envelope) {
      rec.sealedCalls += 1;
      rec.lastEnvelope = envelope;
      return { messageId: 1 };
    },
    async sendPlaintextChannel() {
      rec.plaintextCalls += 1;
      return { messageId: 2 };
    },
  };
  return rec;
}

beforeAll(async () => {
  senderIdentity = await generateKeyPair();
  senderEnc = await generateEncryptionKeyPair();
  memberEnc = await generateEncryptionKeyPair();
});

function allKeyed() {
  return [
    { id: SENDER, encryption_public_key: bufferToBase64(senderEnc.publicKey) },
    { id: MEMBER, encryption_public_key: bufferToBase64(memberEnc.publicKey) },
  ];
}

function oneKeyless() {
  return [...allKeyed(), { id: KEYLESS, encryption_public_key: null }];
}

function input(over: Record<string, unknown> = {}) {
  return {
    senderId: SENDER,
    senderIdentityPrivateKey: bufferToBase64(senderIdentity.privateKey),
    channelId: CHANNEL,
    text: 'to everyone',
    ...over,
  } as any;
}

describe('every member has a key', () => {
  test('the message seals, and every member is addressed', async () => {
    const rec = recording(allKeyed());
    const outcome = await sendChannelVia(rec.transport, input());

    expect(outcome.sealed).toBe(true);
    expect(rec.sealedCalls).toBe(1);
    expect(rec.plaintextCalls).toBe(0);

    const addressed = rec.lastEnvelope.sealed.recipients.map((r: any) => r.entity).sort();
    expect(addressed).toEqual([SENDER, MEMBER].sort());
  });

  test('⚠️ the SENDER can open their own message', async () => {
    // The recipient it is natural to forget. Without it the sender cannot read
    // their own history, and the server rejects the envelope for not matching
    // membership — but only the first of those is visible to a person.
    const rec = recording(allKeyed());
    await sendChannelVia(rec.transport, input({ text: 'mine to read' }));

    expect(
      await openGroup(SENDER, bufferToBase64(senderEnc.privateKey), rec.lastEnvelope.sealed)
    ).toBe('mine to read');
  });

  test('another member opens the same body', async () => {
    // One body, one content key, wrapped per recipient — so this is not a
    // second copy but the same ciphertext opened by a different wrapped key.
    const rec = recording(allKeyed());
    await sendChannelVia(rec.transport, input({ text: 'shared body' }));

    expect(
      await openGroup(MEMBER, bufferToBase64(memberEnc.privateKey), rec.lastEnvelope.sealed)
    ).toBe('shared body');
  });

  test('the envelope is signed by the sender and verifies', async () => {
    const rec = recording(allKeyed());
    await sendChannelVia(rec.transport, input());

    expect(
      await verifyGroupEnvelope(bufferToBase64(senderIdentity.publicKey), rec.lastEnvelope)
    ).toBe(true);
  });

  test('⚠️ the plaintext is nowhere in the envelope', async () => {
    const rec = recording(allKeyed());
    await sendChannelVia(rec.transport, input({ text: 'CHANNEL-SENTINEL-3f7b' }));

    expect(JSON.stringify(rec.lastEnvelope)).not.toContain('CHANNEL-SENTINEL-3f7b');
  });
});

describe('⚠️ one member without a key', () => {
  test('refuses, posts nothing, and NAMES who is missing one', async () => {
    const rec = recording(oneKeyless());

    await expect(sendChannelVia(rec.transport, input())).rejects.toThrow(
      new RegExp(KEYLESS)
    );

    // Nothing sent by either path. A partial seal is the failure this whole
    // check exists to prevent, and "it threw" alone does not rule it out.
    expect(rec.sealedCalls).toBe(0);
    expect(rec.plaintextCalls).toBe(0);
  });

  test('never seals to the subset that does have keys', async () => {
    // The specific shape: sealing to Alice and Bob but not Carol would look
    // like success to the sender while Carol holds a message she can never
    // open. The server refuses it too, but the client must not attempt it —
    // relying on the far side to catch it makes the rule invisible here.
    const rec = recording(oneKeyless());
    await expect(sendChannelVia(rec.transport, input())).rejects.toThrow();
    expect(rec.lastEnvelope).toBeNull();
  });

  test('⚠️ an EMPTY STRING key counts as no key, not as a key', async () => {
    // ADDED BECAUSE A MUTANT SURVIVED. Removing the `=== ''` half of the
    // check left every test here green: this file only ever used `null` for a
    // keyless member, so the empty-string branch was never exercised — while
    // the direct-send tests did cover it. The gap was in the tests, not the
    // mutation, and nothing but the mutant said so.
    //
    // What it would cost: '' passes to `sealToMany` as a public key, producing
    // either a throw deep in WebCrypto or an envelope that member can never
    // open — sealed, delivered, and unreadable to exactly one person.
    // ⚠️ AND THE OBVIOUS ASSERTION HERE IS MASKED, measured: with the check
    // removed, `sealToMany` ALSO throws, and its message ALSO names the entity —
    //
    //     "Recipient carol@example.com has an unusable encryption key.
    //      Refusing to seal a message that entity could never open."
    //
    // so `rejects.toThrow(/carol@…/)` passes either way and proves nothing.
    // Two guards agreeing on outcome, exactly the shape this repo keeps finding.
    //
    // What actually separates them is the DOWNGRADE path: with plaintext
    // allowed, this check sends the message, while `sealToMany` throws and the
    // caller gets an error where they asked for a fallback. So that is what is
    // asserted.
    const rec = recording([...allKeyed(), { id: KEYLESS, encryption_public_key: '' }]);

    const outcome = await sendChannelVia(rec.transport, input({ allowPlaintext: true }));

    expect(outcome.sealed).toBe(false);
    expect(outcome.downgradeReason).toContain(KEYLESS);
    expect(rec.plaintextCalls).toBe(1);
    expect(rec.sealedCalls).toBe(0);
  });

  test('sends unsealed only when explicitly allowed, and says who caused it', async () => {
    const rec = recording(oneKeyless());
    const outcome = await sendChannelVia(rec.transport, input({ allowPlaintext: true }));

    expect(outcome.sealed).toBe(false);
    expect(outcome.downgradeReason).toContain(KEYLESS);
    expect(rec.plaintextCalls).toBe(1);
    expect(rec.sealedCalls).toBe(0);
  });
});

describe('a channel with no members', () => {
  test('is refused rather than sealed to nobody', async () => {
    // `sealToMany` refuses an empty recipient list, but reaching it means the
    // membership lookup returned nothing — which is a different problem with a
    // different message, and the caller should hear that one.
    const rec = recording([]);
    await expect(sendChannelVia(rec.transport, input())).rejects.toThrow(/member/i);
    expect(rec.sealedCalls).toBe(0);
    expect(rec.plaintextCalls).toBe(0);
  });
});
