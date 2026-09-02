import { test, expect, describe, beforeAll, afterAll } from 'bun:test';
import { startServer, stopServer } from '../http';
import { getDatabaseContext } from '../../db';
import { hashToken } from '../../auth/oauth';
import { generateKeyPair, generateEncryptionKeyPair, bufferToBase64 } from '../../crypto/keys';
import { seal } from '../../crypto/sealing';
import { signEnvelope, type SignedEnvelope } from '../../crypto/envelope';

// ============================================================================
// The sealed send, over HTTP.
//
// ⚠️ A SEPARATE ROUTE, NOT A FLAG ON `/messages/send`. The service already
// splits sealed from plaintext into two methods so a caller must NAME the path;
// putting them back together at the edge would undo that one layer up. "Sealed
// if an envelope is present, plaintext otherwise" is a disjunction, and the
// failure it permits is the one this whole increment exists to prevent — a
// client that meant to seal, didn't, and got a 201 anyway.
//
// The route also REFUSES a request carrying both `text` and `envelope`, rather
// than picking one. Two fields that each name a different send path are an
// ambiguity, and resolving an ambiguity silently is how the wrong one gets
// chosen.
// ============================================================================

const TEST_PORT = 17921;
const TEST_HOST = '127.0.0.1';
const URL_BASE = `http://${TEST_HOST}:${TEST_PORT}`;
const TEST_SECRET = process.env.FAM_SERVER_SECRET!;

process.env.FAM_PORT = String(TEST_PORT);
process.env.FAM_HOST = TEST_HOST;

const ACCOUNT = 'sealedroute@example.com';
const ALICE = `alice@${ACCOUNT}`;
const BOB = `bob@${ACCOUNT}`;

type Endpoint = '/messages/send-sealed' | '/messages/send';

let serverHandle: ReturnType<typeof startServer>;
let aliceIdentity: { publicKey: Uint8Array; privateKey: Uint8Array };
let bobEncryption: { publicKey: Uint8Array; privateKey: Uint8Array };

async function post(path: Endpoint, body: unknown): Promise<{ status: number; data: any }> {
  const res = await fetch(`${URL_BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, data: await res.json().catch(() => null) };
}

function sessionFor(entityId: string): string {
  return getDatabaseContext().sessions.create(entityId).id;
}

async function envelopeFor(
  text: string,
  over: Partial<{ sender: string; recipient: string }> = {}
): Promise<SignedEnvelope> {
  const sealed = await seal(bufferToBase64(bobEncryption.publicKey), text);
  return signEnvelope(bufferToBase64(aliceIdentity.privateKey), {
    sender: over.sender ?? ALICE,
    recipient: over.recipient ?? BOB,
    sentAt: new Date().toISOString(),
    sequence: 1,
    sealed,
  });
}

beforeAll(async () => {
  aliceIdentity = await generateKeyPair();
  bobEncryption = await generateEncryptionKeyPair();

  const ctx = getDatabaseContext();
  ctx.db.prepare('INSERT OR IGNORE INTO accounts (id) VALUES (?)').run(ACCOUNT);
  ctx.db
    .prepare(
      `INSERT OR IGNORE INTO authorizations (id, account_id, server_id, token_hash)
       VALUES (?, ?, 'local', ?)`
    )
    .run(`auth-${ACCOUNT}`, ACCOUNT, await hashToken(`token-${ACCOUNT}`, TEST_SECRET));

  ctx.db
    .prepare(
      `INSERT OR IGNORE INTO entities (id, account_id, type, public_key, capabilities)
       VALUES (?, ?, 'agent', ?, '{"can_send":true}')`
    )
    .run(ALICE, ACCOUNT, bufferToBase64(aliceIdentity.publicKey));
  ctx.db
    .prepare(
      `INSERT OR IGNORE INTO entities (id, account_id, type, public_key, capabilities)
       VALUES (?, ?, 'agent', 'pk-bob', '{"can_send":true}')`
    )
    .run(BOB, ACCOUNT);
  ctx.entities.setEncryptionKey(BOB, bufferToBase64(bobEncryption.publicKey));

  serverHandle = startServer({ port: TEST_PORT, host: TEST_HOST });
});

afterAll(() => stopServer(serverHandle));

describe('POST /messages/send-sealed', () => {
  test('stores an envelope the server cannot read and reports delivery', async () => {
    const { status, data } = await post('/messages/send-sealed', {
      session_id: sessionFor(ALICE),
      to_entity: BOB,
      envelope: await envelopeFor('secret payload'),
    });

    expect(status).toBe(201);
    expect(data.message_id).toBeGreaterThan(0);
    // The delivery block is not optional here either: 201 alone says "stored"
    // and gets read as "delivered".
    expect(data.delivery).toBeDefined();
    expect(data.delivery.outcome).toBeDefined();

    const row = getDatabaseContext()
      .db.prepare('SELECT sealed, text FROM messages WHERE id = ?')
      .get(data.message_id) as { sealed: number; text: string };
    expect(row.sealed).toBe(1);
    expect(row.text).not.toContain('secret payload');
  });

  test('an unauthenticated call is refused', async () => {
    const { status } = await post('/messages/send-sealed', {
      to_entity: BOB,
      envelope: await envelopeFor('x'),
    });
    expect(status).toBe(401);
  });

  test('a missing envelope says so, rather than listing every absent field', async () => {
    // ⚠️ MASKED ON STATUS ALONE, measured: removing the route's guard entirely
    // still gives 400, because the service's shape check rejects `undefined`.
    // Asserting the status would leave this guard invisible and it would be
    // deleted as redundant the next time someone tidied the route.
    //
    // What it is for is the MESSAGE. A caller who forgot the field gets
    // "Missing envelope"; without the guard they get a list of eleven fields
    // that are all missing because the object is not there — technically true
    // and useless for the mistake actually made.
    const { status, data } = await post('/messages/send-sealed', {
      session_id: sessionFor(ALICE),
      to_entity: BOB,
    });

    expect(status).toBe(400);
    expect(data.error).toBe('Missing envelope');
    expect(data.error).not.toMatch(/ephemeralPublicKey/);
  });

  test('sending BOTH text and an envelope is refused rather than resolved', async () => {
    // ⚠️ The ambiguity that matters. Two fields naming two different send paths
    // is not a request with a sensible default — whichever the server picked,
    // half of callers would be surprised, and the surprising half sends
    // plaintext believing it sealed.
    const { status, data } = await post('/messages/send-sealed', {
      session_id: sessionFor(ALICE),
      to_entity: BOB,
      text: 'plaintext',
      envelope: await envelopeFor('sealed'),
    });

    expect(status).toBe(400);
    expect(data.error).toMatch(/both/i);
  });

  test('an envelope whose addressing disagrees with the request is refused', async () => {
    // The service enforces this; the route must not have its own opinion.
    // Present here so the rule is covered through the surface a client uses.
    const { status } = await post('/messages/send-sealed', {
      session_id: sessionFor(ALICE),
      to_entity: BOB,
      envelope: await envelopeFor('x', { recipient: ALICE }),
    });
    expect(status).toBe(400);
  });

  test('a missing recipient is refused', async () => {
    const { status } = await post('/messages/send-sealed', {
      session_id: sessionFor(ALICE),
      envelope: await envelopeFor('x'),
    });
    expect(status).toBe(400);
  });
});

describe('the plaintext route is unchanged', () => {
  test('it still sends, and still marks the row NOT sealed', async () => {
    // The control. A change that broke the plaintext path while adding the
    // sealed one would otherwise show up only in someone else's suite.
    const { status, data } = await post('/messages/send', {
      session_id: sessionFor(ALICE),
      to_entity: BOB,
      text: 'ordinary message',
    });

    expect(status).toBe(201);
    const row = getDatabaseContext()
      .db.prepare('SELECT sealed FROM messages WHERE id = ?')
      .get(data.message_id) as { sealed: number };
    expect(row.sealed).toBe(0);
  });

  test('it does NOT accept an envelope', async () => {
    // If the plaintext route quietly accepted an envelope field it would be the
    // disjunction this split exists to remove, reintroduced at the edge.
    const { status } = await post('/messages/send', {
      session_id: sessionFor(ALICE),
      to_entity: BOB,
      envelope: await envelopeFor('x'),
    });
    expect(status).toBe(400);
  });
});
