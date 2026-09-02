import { test, expect, describe, beforeEach, afterEach } from 'bun:test';
import { Database } from 'bun:sqlite';
import { createContext } from '../../db/transaction';
import { initializeDatabase } from '../../db/schema';
import { AccountRepository } from '../../db/repositories/account';
import { WebSocketManager } from '../websocket';
import { MessageSendService } from '../services/messageSend';
import { PermissionChecker } from '../services/permissionChecker';
import { generateKeyPair, generateEncryptionKeyPair, bufferToBase64 } from '../../crypto/keys';
import { seal } from '../../crypto/sealing';
import { signEnvelope, signGroupEnvelope, type SignedEnvelope } from '../../crypto/envelope';
import { sealToMany } from '../../crypto/groupSealing';

// ============================================================================
// The sealed path over WebSocket.
//
// ⚠️ THIS EXISTS BECAUSE HTTP HAVING IT AND WS NOT HAVING IT IS THE SHAPE THIS
// REPO ALREADY DECIDED AGAINST. `MessageSendService` is the single authoritative
// send path precisely so the two surfaces cannot answer differently — and a
// capability present on one and absent on the other is the version of that
// divergence nobody files as a bug, because neither surface is WRONG.
//
// A `send_sealed` frame, mirroring POST /messages/send-sealed exactly: separate
// from `send` rather than a flag on it, both-fields refused rather than
// resolved, and no opinion of its own about envelope validity.
// ============================================================================

function mockWs() {
  const sent: any[] = [];
  return {
    sent,
    send(data: string) {
      sent.push(JSON.parse(data));
    },
    close() {},
  };
}

describe('WebSocket send_sealed', () => {
  const ACCOUNT = 'wssealed.example.com';
  const ALICE = `alice@${ACCOUNT}`;
  const BOB = `bob@${ACCOUNT}`;

  let db: Database;
  let ctx: ReturnType<typeof createContext>;
  let wsManager: WebSocketManager;
  let ws: ReturnType<typeof mockWs>;
  let aliceIdentity: { publicKey: Uint8Array; privateKey: Uint8Array };
  let bobEncryption: { publicKey: Uint8Array; privateKey: Uint8Array };

  beforeEach(async () => {
    db = new Database(':memory:');
    initializeDatabase(db);
    ctx = createContext(db);

    aliceIdentity = await generateKeyPair();
    bobEncryption = await generateEncryptionKeyPair();

    new AccountRepository(db).create(ACCOUNT, 'Test');
    ctx.entities.create(ALICE, ACCOUNT, 'agent', bufferToBase64(aliceIdentity.publicKey));
    ctx.entities.create(BOB, ACCOUNT, 'agent', 'pk-bob');
    ctx.entities.setEncryptionKey(BOB, bufferToBase64(bobEncryption.publicKey));

    wsManager = new WebSocketManager(ctx);
    wsManager.setSendService(
      new MessageSendService(ctx, wsManager, new PermissionChecker(ctx))
    );

    ws = mockWs();
    const session = ctx.sessions.create(ALICE);
    wsManager.handleConnection(ws, ALICE, session.id);
    ws.sent.length = 0; // drop the connection frames
  });

  afterEach(() => {
    wsManager.shutdown();
    db.close();
  });

  async function envelopeFor(
    text: string,
    over: Partial<{ recipient: string }> = {}
  ): Promise<SignedEnvelope> {
    const sealed = await seal(bufferToBase64(bobEncryption.publicKey), text);
    return signEnvelope(bufferToBase64(aliceIdentity.privateKey), {
      sender: ALICE,
      recipient: over.recipient ?? BOB,
      sentAt: new Date().toISOString(),
      sequence: 1,
      sealed,
    });
  }

  function lastSystemText(): string {
    const frames = ws.sent.filter((f) => f.from === 'system');
    return frames.length > 0 ? frames[frames.length - 1]!.text : '';
  }

  test('a sealed frame is stored, marked sealed, and acknowledged', async () => {
    await wsManager.handleMessage(
      ws,
      JSON.stringify({ type: 'send_sealed', to: BOB, envelope: await envelopeFor('over the wire') })
    );

    const ack = ws.sent.find((f) => f.type === 'ack');
    expect(ack).toBeDefined();
    expect(ack.message_id).toBeGreaterThan(0);

    const row = db
      .prepare('SELECT sealed, text FROM messages WHERE id = ?')
      .get(ack.message_id) as { sealed: number; text: string };
    expect(row.sealed).toBe(1);
    expect(row.text).not.toContain('over the wire');
  });

  test('the ack reports delivery, not merely storage', async () => {
    // Same defect the HTTP 201 had: a bare ack confirms the row and gets read
    // as "the recipient has it".
    await wsManager.handleMessage(
      ws,
      JSON.stringify({ type: 'send_sealed', to: BOB, envelope: await envelopeFor('x') })
    );

    const ack = ws.sent.find((f) => f.type === 'ack');
    expect(ack.delivery).toBeDefined();
    expect(ack.delivery.outcome).toBeDefined();
  });

  test('an ordinary send is still NOT sealed', async () => {
    // The control. Without it `sealed` could be 1 for everything.
    await wsManager.handleMessage(ws, JSON.stringify({ type: 'send', to: BOB, text: 'plain' }));

    const ack = ws.sent.find((f) => f.type === 'ack');
    const row = db
      .prepare('SELECT sealed FROM messages WHERE id = ?')
      .get(ack.message_id) as { sealed: number };
    expect(row.sealed).toBe(0);
  });

  test('sending BOTH text and an envelope is refused rather than resolved', async () => {
    await wsManager.handleMessage(
      ws,
      JSON.stringify({
        type: 'send_sealed',
        to: BOB,
        text: 'plaintext',
        envelope: await envelopeFor('sealed'),
      })
    );

    expect(lastSystemText()).toMatch(/both/i);
    expect(db.prepare('SELECT COUNT(*) as n FROM messages').get()).toEqual({ n: 0 });
  });

  test('a missing envelope is refused as missing, not as malformed', async () => {
    // ⚠️ MY FIRST VERSION OF THIS TEST WAS MASKED BY ITS OWN REGEX, and the
    // cause is worth more than the fix.
    //
    // It asserted `/envelope/i`. Deleting the guard entirely still passed,
    // because the service's fallback says "Malformed sealed envelope: missing
    // or wrong type: ..." — which contains the word "envelope". The assertion
    // could not tell the guard's message from the message that appears when the
    // guard is gone.
    //
    // This is the fourth guard-masked-by-a-later-check in this series, and the
    // first where the masking was caused by the ASSERTION rather than the code.
    // I had already fixed exactly this in the HTTP route by asserting the exact
    // string, then wrote a loose regex here — the lesson did not transfer
    // because I never checked what the fallback actually says.
    await wsManager.handleMessage(ws, JSON.stringify({ type: 'send_sealed', to: BOB }));

    expect(lastSystemText()).toBe('A sealed send requires an envelope.');
    expect(lastSystemText()).not.toMatch(/malformed/i);
    expect(db.prepare('SELECT COUNT(*) as n FROM messages').get()).toEqual({ n: 0 });
  });

  test('a sealed CHANNEL send works over the socket', async () => {
    // This test previously asserted "not supported yet" — the honest answer
    // while channel wrapping was unbuilt. Now that it exists the assertion is
    // replaced rather than deleted, because "the refusal message changed" and
    // "the feature works" are different claims and only the second one is worth
    // having. A stale test asserting an old refusal would have kept passing and
    // quietly documented the feature as absent.
    const aliceEncryption = await generateEncryptionKeyPair();
    ctx.entities.setEncryptionKey(ALICE, bufferToBase64(aliceEncryption.publicKey));

    const channel = ctx.channels.create('ws-room', ALICE, false);
    ctx.channels.addMember(channel.id, ALICE, 'owner');
    ctx.channels.addMember(channel.id, BOB, 'member');

    const sealed = await sealToMany(
      [
        { entity: ALICE, publicKey: bufferToBase64(aliceEncryption.publicKey) },
        { entity: BOB, publicKey: bufferToBase64(bobEncryption.publicKey) },
      ],
      'to the room'
    );
    const envelope = await signGroupEnvelope(bufferToBase64(aliceIdentity.privateKey), {
      sender: ALICE,
      channel: channel.id,
      sentAt: new Date().toISOString(),
      sequence: 1,
      sealed,
    });

    await wsManager.handleMessage(
      ws,
      JSON.stringify({ type: 'send_sealed', channel: channel.id, envelope })
    );

    const ack = ws.sent.find((f) => f.type === 'ack');
    expect(ack).toBeDefined();
    const row = db
      .prepare('SELECT sealed, text FROM messages WHERE id = ?')
      .get(ack.message_id) as { sealed: number; text: string };
    expect(row.sealed).toBe(1);
    expect(row.text).not.toContain('to the room');
  });

  test('naming both "to" and "channel" is refused rather than resolved', async () => {
    await wsManager.handleMessage(
      ws,
      JSON.stringify({
        type: 'send_sealed',
        to: BOB,
        channel: 'some-channel',
        envelope: await envelopeFor('x'),
      })
    );

    expect(lastSystemText()).toMatch(/not both/i);
  });

  test('an envelope disagreeing with the routing is refused, and the error reaches the client', async () => {
    // The service enforces it; what this checks is that a thrown FamError
    // becomes a system frame rather than an unhandled rejection that leaves the
    // client waiting for an ack forever.
    await wsManager.handleMessage(
      ws,
      JSON.stringify({
        type: 'send_sealed',
        to: BOB,
        envelope: await envelopeFor('x', { recipient: ALICE }),
      })
    );

    expect(lastSystemText()).toMatch(/recipient/i);
    expect(ws.sent.find((f) => f.type === 'ack')).toBeUndefined();
    expect(db.prepare('SELECT COUNT(*) as n FROM messages').get()).toEqual({ n: 0 });
  });
});
