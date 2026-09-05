import { test, expect, describe, beforeAll, afterAll } from 'bun:test';
import { startServer, stopServer } from '../../../server/http';
import { getDatabaseContext } from '../../../db';
import { hashToken } from '../../../auth/oauth';
import { generateKeyPair, generateEncryptionKeyPair, bufferToBase64 } from '../../../crypto/keys';
import { openGroup } from '../../../crypto/groupSealing';
import { sendToChannel } from '../sendMessage';

// ============================================================================
// ⚠️ AGAINST THE REAL SERVER, BECAUSE THE SERVER IS THE STRICT ONE.
//
// `sendChannelVia` has unit tests with a fake transport, and they prove the
// POLICY. They cannot prove the envelope this client builds is one the server
// will accept — and the server checks three things the fake never will:
//
//   - the recipient set must EQUAL the membership, in both directions
//   - every member must have a published key
//   - the group signature must verify against the sender's identity key
//
// A client that got any of those wrong would pass every unit test and fail on
// the first real send. This file is what makes "a channel message travels
// sealed" a claim about the deployment rather than about the policy module.
// ============================================================================

const TEST_PORT = 17991;
const TEST_HOST = '127.0.0.1';
const TEST_SECRET = process.env.FAM_SERVER_SECRET!;

process.env.FAM_PORT = String(TEST_PORT);
process.env.FAM_HOST = TEST_HOST;

const ACCOUNT = 'sendchannel@example.com';
const ALICE = `alice@${ACCOUNT}`;
const BOB = `bob@${ACCOUNT}`;
const CAROL = `carol@${ACCOUNT}`;

const config = { serverUrl: `http://${TEST_HOST}:${TEST_PORT}` } as any;

let serverHandle: ReturnType<typeof startServer>;
let aliceIdentityPrivate: string;
let alicePrivEnc: string;
let bobPrivEnc: string;
let sealedChannel: string;
let mixedChannel: string;

function sessionFor(entityId: string): string {
  return getDatabaseContext().sessions.create(entityId).id;
}

function lastMessage(): { text: string; sealed: number; channel_id: string } {
  return getDatabaseContext()
    .db.prepare('SELECT text, sealed, channel_id FROM messages ORDER BY id DESC LIMIT 1')
    .get() as any;
}

function messageCount(): number {
  return (
    getDatabaseContext().db.prepare('SELECT COUNT(*) as n FROM messages').get() as { n: number }
  ).n;
}

beforeAll(async () => {
  const ctx = getDatabaseContext();
  ctx.db.prepare('INSERT OR IGNORE INTO accounts (id) VALUES (?)').run(ACCOUNT);
  ctx.db
    .prepare(
      `INSERT OR IGNORE INTO authorizations (id, account_id, server_id, token_hash)
       VALUES (?, ?, 'local', ?)`
    )
    .run(`auth-${ACCOUNT}`, ACCOUNT, await hashToken(`token-${ACCOUNT}`, TEST_SECRET));

  const aliceKeys = await generateKeyPair();
  aliceIdentityPrivate = bufferToBase64(aliceKeys.privateKey);

  for (const [id, keys] of [
    [ALICE, aliceKeys],
    [BOB, await generateKeyPair()],
    [CAROL, await generateKeyPair()],
  ] as Array<[string, { publicKey: Uint8Array }]>) {
    ctx.db
      .prepare(
        `INSERT OR IGNORE INTO entities (id, account_id, type, public_key, capabilities)
         VALUES (?, ?, 'agent', ?, '{"can_send":true,"can_receive":true,"can_join_channel":true}')`
      )
      .run(id, ACCOUNT, bufferToBase64(keys.publicKey));
  }

  const aliceEnc = await generateEncryptionKeyPair();
  const bobEnc = await generateEncryptionKeyPair();
  alicePrivEnc = bufferToBase64(aliceEnc.privateKey);
  bobPrivEnc = bufferToBase64(bobEnc.privateKey);
  ctx.entities.setEncryptionKey(ALICE, bufferToBase64(aliceEnc.publicKey));
  ctx.entities.setEncryptionKey(BOB, bufferToBase64(bobEnc.publicKey));
  // CAROL deliberately gets none: she is every entity created before publishing
  // shipped, and the reason a channel containing her cannot be sealed at all.

  const sealed = ctx.channels.create('sealed-room', ALICE, false);
  ctx.channels.addMember(sealed.id, BOB);
  sealedChannel = sealed.id;

  const mixed = ctx.channels.create('mixed-room', ALICE, false);
  ctx.channels.addMember(mixed.id, BOB);
  ctx.channels.addMember(mixed.id, CAROL);
  mixedChannel = mixed.id;

  serverHandle = startServer({ port: TEST_PORT, host: TEST_HOST });
});

afterAll(() => stopServer(serverHandle));

describe('a channel where every member has a key', () => {
  test('⚠️ the server ACCEPTS the envelope this client builds', async () => {
    // The load-bearing one. The server rejects a recipient set that differs
    // from the membership in either direction, and rejects a signature that
    // does not verify. Passing here means the client satisfied all of it.
    const outcome = await sendToChannel(config, {
      senderId: ALICE,
      senderIdentityPrivateKey: aliceIdentityPrivate,
      sessionId: sessionFor(ALICE),
      channelId: sealedChannel,
      text: 'CHANNEL-BODY-8a4f',
    });

    expect(outcome.sealed).toBe(true);

    const row = lastMessage();
    expect(row.sealed).toBe(1);
    expect(row.channel_id).toBe(sealedChannel);
    expect(row.text).not.toContain('CHANNEL-BODY-8a4f');
  });

  test('both members open the same stored body', async () => {
    await sendToChannel(config, {
      senderId: ALICE,
      senderIdentityPrivateKey: aliceIdentityPrivate,
      sessionId: sessionFor(ALICE),
      channelId: sealedChannel,
      text: 'read by both',
    });

    const envelope = JSON.parse(lastMessage().text);

    // The sender reads their own message — the recipient it is natural to omit.
    expect(await openGroup(ALICE, alicePrivEnc, envelope.sealed)).toBe('read by both');
    expect(await openGroup(BOB, bobPrivEnc, envelope.sealed)).toBe('read by both');
  });
});

describe('⚠️ a channel with one keyless member', () => {
  test('refuses, sends nothing, and names who is missing a key', async () => {
    const before = messageCount();

    await expect(
      sendToChannel(config, {
        senderId: ALICE,
        senderIdentityPrivateKey: aliceIdentityPrivate,
        sessionId: sessionFor(ALICE),
        channelId: mixedChannel,
        text: 'should not be sent',
      })
    ).rejects.toThrow(new RegExp(CAROL));

    expect(messageCount()).toBe(before);
  });

  test('sends unsealed when explicitly allowed, and the row records that', async () => {
    const outcome = await sendToChannel(config, {
      senderId: ALICE,
      senderIdentityPrivateKey: aliceIdentityPrivate,
      sessionId: sessionFor(ALICE),
      channelId: mixedChannel,
      text: 'deliberately unsealed',
      allowPlaintext: true,
    });

    expect(outcome.sealed).toBe(false);
    expect(outcome.downgradeReason).toContain(CAROL);

    // The DATABASE, not the return value: `sealed` is what a reader consults.
    const row = lastMessage();
    expect(row.sealed).toBe(0);
    expect(row.text).toBe('deliberately unsealed');
  });
});
