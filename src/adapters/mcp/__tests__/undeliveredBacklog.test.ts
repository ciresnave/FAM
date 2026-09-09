import { test, expect, describe, beforeAll, beforeEach } from 'bun:test';
import { mkdtemp } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { ChannelPushHandler } from '../channel-push';
import { generateKeyPair, generateEncryptionKeyPair, bufferToBase64 } from '../../../crypto/keys';
import { prepareSealedDirect } from '../../../crypto/outgoing';

// ============================================================================
// ⚠️ THE BACKLOG PATH IS THE SIBLING OF THE LIVE PATH AND EVERY GUARD WAS
// WRITTEN ON THE OTHER BRANCH.
//
// `handleMessage` opens the envelope, checks the signature, consults the replay
// window and reports `sealed` and `sender_vouched`. `handleUndelivered` did none
// of it: it pushed `message.text` — the envelope — straight into an agent's
// context, then acknowledged the whole batch unconditionally.
//
// Observed, arriving at a real non-Claude MCP client against a live server:
//
//     {"version":1,"sender":"…","sealed":{"ciphertext":"qf/Zfhnq…"},"signature":"…"}
//
// That is verbatim the failure the comment on the live branch exists to prevent.
//
// ⚠️ AND THE ACK IS WORSE THAN THE RENDERING. `markDelivered` ran after pushing
// to a channel that CANNOT ACKNOWLEDGE — an MCP notification has no id and no
// response. So a client that authenticated without registering a handler
// consumed and permanently destroyed its own backlog, silently on both sides.
//
// ⚠️ WHAT THESE TESTS DO NOT COVER, STATED SO THE GREEN IS NOT READ AS MORE THAN
// IT IS: the adapter cannot detect a LIVE pipe that nobody is reading. Nothing
// here fixes that, and nothing can, inside this file. What is fixed is the two
// cases the adapter CAN see — a push that throws, and a message that will not
// open. The residual is recorded in DESIGN-SYNAPSE-HANDOVER.md.
// ============================================================================

let stores: { seenPath: string; anchorsPath: string };

beforeEach(async () => {
  const dir = await mkdtemp(join(tmpdir(), 'fam-backlog-'));
  stores = { seenPath: join(dir, 'seen.json'), anchorsPath: join(dir, 'anchors.json') };
});

let alice: { publicKey: Uint8Array; privateKey: Uint8Array };
let bobEnc: { publicKey: Uint8Array; privateKey: Uint8Array };

const ALICE = 'alice@example.com';
const BOB = 'bob@example.com';

beforeAll(async () => {
  alice = await generateKeyPair();
  bobEnc = await generateEncryptionKeyPair();
});

/** Captures pushes, and can be told to fail the way a dead pipe fails. */
function fakeMcp(opts: { throwOnPush?: boolean } = {}) {
  const pushed: Array<{ content: string; meta: any }> = [];
  return {
    pushed,
    server: {
      async notification(n: any) {
        if (opts.throwOnPush) throw new Error('EPIPE: broken pipe, write');
        pushed.push({ content: n.params.content, meta: n.params.meta });
      },
    } as any,
  };
}

/** Records what the handler acknowledged, which is the thing under test. */
function fakeClient(directory: Array<{ id: string; public_key: string }>) {
  const acked: number[] = [];
  return {
    acked,
    client: {
      async listEntities() {
        return directory as any;
      },
      async markDelivered(ids: number[]) {
        acked.push(...ids);
      },
      onMessage() {},
      onUndeliveredMessages() {},
      onInvitation() {},
      offMessage() {},
      offUndeliveredMessages() {},
      offInvitation() {},
    } as any,
  };
}

const aliceDirectory = () => [{ id: ALICE, public_key: bufferToBase64(alice.publicKey) }];

/** A backlog row as `/entities/authenticate` returns it. */
async function sealedBacklogRow(id: number, text: string) {
  const decision = await prepareSealedDirect({
    senderId: ALICE,
    senderIdentityPrivateKey: bufferToBase64(alice.privateKey),
    recipientId: BOB,
    recipientEncryptionPublicKey: bufferToBase64(bobEnc.publicKey),
    text,
    sequence: id,
  });
  if (!decision.sealed) throw new Error('fixture should seal');
  return {
    id,
    from_entity: ALICE,
    to_entity: BOB,
    channel_id: null,
    text: JSON.stringify(decision.envelope),
    sent_at: new Date().toISOString(),
    delivered: 0,
    sealed: true,
  };
}

function plainBacklogRow(id: number, text: string) {
  return {
    id,
    from_entity: ALICE,
    to_entity: BOB,
    channel_id: null,
    text,
    sent_at: new Date().toISOString(),
    delivered: 0,
    sealed: false,
  };
}

function handlerFor(mcp: ReturnType<typeof fakeMcp>, client: any, encPriv?: Uint8Array) {
  return new ChannelPushHandler(
    mcp.server,
    client,
    'Bob',
    bufferToBase64(encPriv ?? bobEnc.privateKey),
    BOB,
    stores
  );
}

/** Reach the private handler the client would have invoked. */
function deliverBacklog(handler: ChannelPushHandler, rows: unknown[]): Promise<void> {
  return (handler as any).handleUndelivered(rows);
}

describe('the offline backlog gets the guards the live path already had', () => {
  test('⚠️ a sealed backlog message arrives OPENED, not as envelope JSON', async () => {
    const mcp = fakeMcp();
    const { client } = fakeClient(aliceDirectory());
    const handler = handlerFor(mcp, client);

    await deliverBacklog(handler, [await sealedBacklogRow(1, 'the backlog message')]);

    expect(mcp.pushed).toHaveLength(1);
    expect(mcp.pushed[0]!.content).toBe('the backlog message');
    // The envelope must not survive anywhere in what was pushed.
    expect(mcp.pushed[0]!.content).not.toContain('ciphertext');
  });

  test('the push reports `sealed`, so a reader can tell how it arrived', async () => {
    const mcp = fakeMcp();
    const { client } = fakeClient(aliceDirectory());
    const handler = handlerFor(mcp, client);

    await deliverBacklog(handler, [await sealedBacklogRow(2, 'sealed backlog')]);

    expect(mcp.pushed[0]!.meta.sealed).toBe(true);
    expect(mcp.pushed[0]!.meta.offline_backlog).toBe(true);
  });

  test('control: a PLAIN backlog message still arrives, unchanged', async () => {
    // ⚠️ Without this, every assertion above passes against a handler that has
    // started refusing everything — a different defect wearing the same green.
    const mcp = fakeMcp();
    const { client } = fakeClient(aliceDirectory());
    const handler = handlerFor(mcp, client);

    await deliverBacklog(handler, [plainBacklogRow(3, 'plain backlog text')]);

    expect(mcp.pushed).toHaveLength(1);
    expect(mcp.pushed[0]!.content).toBe('plain backlog text');
    expect(mcp.pushed[0]!.meta.sealed).toBe(false);
  });
});

describe('⚠️ the backlog is acknowledged only for what was actually delivered', () => {
  test('a message that OPENED is acknowledged — the control for both tests below', async () => {
    const mcp = fakeMcp();
    const { client, acked } = fakeClient(aliceDirectory());
    const handler = handlerFor(mcp, client);

    await deliverBacklog(handler, [await sealedBacklogRow(4, 'opens fine')]);

    expect(acked).toEqual([4]);
  });

  test('🔴 a push that THROWS is NOT acknowledged — the dead-pipe client', async () => {
    // The adapter CAN see this one: writing to a closed stdio pipe raises EPIPE.
    // Acking it destroyed a backlog that nothing had received.
    const mcp = fakeMcp({ throwOnPush: true });
    const { client, acked } = fakeClient(aliceDirectory());
    const handler = handlerFor(mcp, client);

    await deliverBacklog(handler, [await sealedBacklogRow(5, 'never lands')]);

    expect(mcp.pushed).toHaveLength(0);
    expect(acked).toEqual([]);
  });

  test('🔴 a message that CANNOT BE OPENED is NOT acknowledged — it survives for a retry', async () => {
    // Sealed to Bob's key, opened with the WRONG key. Today this is rendered as
    // "[not shown] …" and then acked, so the message is destroyed and can never
    // be re-read once the right key is present.
    const wrongKey = await generateEncryptionKeyPair();
    const mcp = fakeMcp();
    const { client, acked } = fakeClient(aliceDirectory());
    const handler = handlerFor(mcp, client, wrongKey.privateKey);

    await deliverBacklog(handler, [await sealedBacklogRow(6, 'unreadable here')]);

    // It is still SHOWN — withholding it silently would be its own defect — but
    // it is not acknowledged, because rendering a refusal is not delivery.
    expect(mcp.pushed).toHaveLength(1);
    expect(mcp.pushed[0]!.content).toContain('[not shown]');
    expect(acked).toEqual([]);
  });

  test('⚠️ a REPLAYED message IS acknowledged — withholding it would replay forever', async () => {
    // The case the first draft of the fix got wrong, and the reason `deliverable`
    // is not `kind === 'opened'`. A replay means this message was ALREADY
    // delivered. Not acking it re-offers it on every reconnect, rendering
    // "[not shown] … replay" into an agent's context each time — trading a
    // silent loss for a permanent noise floor.
    const mcp = fakeMcp();
    const { client, acked } = fakeClient(aliceDirectory());
    const handler = handlerFor(mcp, client);

    const row = await sealedBacklogRow(9, 'delivered once already');
    await deliverBacklog(handler, [row]);
    expect(acked).toEqual([9]);

    // Same message again — now inside the replay window.
    await deliverBacklog(handler, [row]);

    expect(mcp.pushed).toHaveLength(2);
    expect(mcp.pushed[1]!.content).toContain('[not shown]');
    expect(acked).toEqual([9, 9]);
  });

  test('a mixed batch acknowledges only the ones that opened', async () => {
    const mcp = fakeMcp();
    const { client, acked } = fakeClient(aliceDirectory());
    const handler = handlerFor(mcp, client);

    await deliverBacklog(handler, [
      await sealedBacklogRow(7, 'opens'),
      plainBacklogRow(8, 'also fine'),
    ]);

    expect(acked.sort()).toEqual([7, 8]);
  });
});
