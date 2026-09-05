import { test, expect, describe, beforeAll } from 'bun:test';
import { ChannelPushHandler } from '../channel-push';
import { generateKeyPair, generateEncryptionKeyPair, bufferToBase64 } from '../../../crypto/keys';
import { prepareSealedDirect } from '../../../crypto/outgoing';

// ============================================================================
// ⚠️ THE WIRING, NOT THE LOGIC. `readIncoming` has its own unit tests; this
// file exists because those tests pass whether or not anything CALLS it.
//
// That gap has already cost once here: a key-file format change was tested on
// the writer and not on its three readers, and every one of them broke. "The
// format was tested; the readers were not" is the same shape as "the opener was
// tested; the push handler was not".
//
// What a failure here looks like: an agent's context receives
//
//     {"version":1,"sender":"…","recipient":"…","sealed":{"ciphertext":"…"}}
//
// as though a person had written it, with nothing anywhere reporting a problem.
// ============================================================================

let alice: { publicKey: Uint8Array; privateKey: Uint8Array };
let mallory: { publicKey: Uint8Array; privateKey: Uint8Array };
let bobEnc: { publicKey: Uint8Array; privateKey: Uint8Array };

const ALICE = 'alice@example.com';
const BOB = 'bob@example.com';

/** Captures what the handler would push into an agent's context. */
function fakeMcp() {
  const pushed: Array<{ content: string; meta: any }> = [];
  return {
    pushed,
    server: {
      async notification(n: any) {
        pushed.push({ content: n.params.content, meta: n.params.meta });
      },
    } as any,
  };
}

function fakeClient(directory: Array<{ id: string; public_key: string }>) {
  return {
    async listEntities() {
      return directory as any;
    },
    async markDelivered() {},
    onMessage() {},
    onUndeliveredMessages() {},
    onInvitation() {},
    offMessage() {},
    offUndeliveredMessages() {},
    offInvitation() {},
  } as any;
}

beforeAll(async () => {
  alice = await generateKeyPair();
  mallory = await generateKeyPair();
  bobEnc = await generateEncryptionKeyPair();
});

async function sealedPush(signer: Uint8Array, text: string) {
  const decision = await prepareSealedDirect({
    senderId: ALICE,
    senderIdentityPrivateKey: bufferToBase64(signer),
    recipientId: BOB,
    recipientEncryptionPublicKey: bufferToBase64(bobEnc.publicKey),
    text,
    sequence: 1,
  });
  if (!decision.sealed) throw new Error('fixture should seal');

  return {
    type: 'message' as const,
    from: ALICE,
    channel: null,
    to: BOB,
    text: JSON.stringify(decision.envelope),
    sealed: true,
    timestamp: new Date().toISOString(),
    message_id: 1,
  };
}

const aliceDirectory = () => [{ id: ALICE, public_key: bufferToBase64(alice.publicKey) }];

/**
 * Every string anywhere in a value.
 *
 * Used instead of `JSON.stringify(...).not.toContain(...)`, which says
 * "serialise this and search the text" when the actual claim is "no string
 * ANYWHERE in what was pushed is, or contains, the forged body". The direct
 * form does not depend on serialisation at all — key ordering, key names and
 * escaping are all irrelevant to the property being asserted.
 */
function allStrings(value: unknown, out: string[] = []): string[] {
  if (typeof value === 'string') out.push(value);
  else if (Array.isArray(value)) for (const v of value) allStrings(v, out);
  else if (value && typeof value === 'object') {
    for (const v of Object.values(value)) allStrings(v, out);
  }
  return out;
}

/** Reach the private handler the client would have invoked. */
function deliver(handler: ChannelPushHandler, push: unknown): Promise<void> {
  return (handler as any).handleMessage(push);
}

describe('a sealed push reaching an agent', () => {
  test('⚠️ arrives OPENED, not as envelope JSON', async () => {
    const mcp = fakeMcp();
    const handler = new ChannelPushHandler(
      mcp.server,
      fakeClient(aliceDirectory()),
      'Bob',
      bufferToBase64(bobEnc.privateKey)
    );

    await deliver(handler, await sealedPush(alice.privateKey, 'the actual message'));

    expect(mcp.pushed).toHaveLength(1);
    expect(mcp.pushed[0]!.content).toBe('the actual message');
    // The envelope must not survive anywhere in what was pushed.
    expect(mcp.pushed[0]!.content).not.toContain('ciphertext');
  });

  test('the push says it was sealed, so the agent can tell', async () => {
    const mcp = fakeMcp();
    const handler = new ChannelPushHandler(
      mcp.server,
      fakeClient(aliceDirectory()),
      'Bob',
      bufferToBase64(bobEnc.privateKey)
    );

    await deliver(handler, await sealedPush(alice.privateKey, 'x'));
    expect(mcp.pushed[0]!.meta.sealed).toBe(true);
  });
});

describe('⚠️ a forged sealed push', () => {
  test('is withheld, and its text never reaches the agent', async () => {
    // Mallory seals to Bob's PUBLISHED key — public by construction — claiming
    // to be Alice. It decrypts perfectly. Only the signature disagrees.
    const mcp = fakeMcp();
    const handler = new ChannelPushHandler(
      mcp.server,
      fakeClient(aliceDirectory()),
      'Bob',
      bufferToBase64(bobEnc.privateKey)
    );

    await deliver(handler, await sealedPush(mallory.privateKey, 'FORGED-SENTINEL-11c2'));

    expect(mcp.pushed).toHaveLength(1);
    expect(mcp.pushed[0]!.content).toContain('[not shown]');
    expect(
      allStrings(mcp.pushed[0]).filter((v) => v.includes('FORGED-SENTINEL-11c2'))
    ).toEqual([]);
  });
});

describe('an entity with no encryption key', () => {
  test('is told why, and is not shown the envelope', async () => {
    const mcp = fakeMcp();
    const handler = new ChannelPushHandler(
      mcp.server,
      fakeClient(aliceDirectory()),
      'Bob',
      null
    );

    await deliver(handler, await sealedPush(alice.privateKey, 'unreachable body'));

    expect(mcp.pushed[0]!.content).toMatch(/no encryption key|publish/i);
    expect(mcp.pushed[0]!.content).not.toContain('ciphertext');
  });
});

describe('an unsealed push', () => {
  test('is passed through unchanged', async () => {
    // Control: the handler has not become one that mangles ordinary messages.
    const mcp = fakeMcp();
    const handler = new ChannelPushHandler(
      mcp.server,
      fakeClient(aliceDirectory()),
      'Bob',
      bufferToBase64(bobEnc.privateKey)
    );

    await deliver(handler, {
      type: 'message',
      from: ALICE,
      channel: null,
      to: BOB,
      text: 'plain and ordinary',
      timestamp: new Date().toISOString(),
      message_id: 2,
    });

    expect(mcp.pushed[0]!.content).toBe('plain and ordinary');
    expect(mcp.pushed[0]!.meta.sealed).toBe(false);
  });
});
