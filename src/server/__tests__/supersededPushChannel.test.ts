import { test, expect, describe, beforeAll, afterAll } from 'bun:test';
import { startServer, stopServer } from '../http';
import { getDatabaseContext } from '../../db';
import { generateKeyPair, bufferToBase64 } from '../../crypto/keys';
import { createChallengeResponse } from '../../crypto/challenge';

// ============================================================================
// ⚠️ DOES SUPERSESSION ACTUALLY STOP DELIVERY, OR ONLY STOP REQUESTS?
//
// The instance-claim mechanism invalidates a superseded instance's SESSION, so
// its next HTTP call answers 401. But a WebSocket is validated ONCE, at
// `handleConnection`, and after that the connection lives in the manager's
// in-memory maps:
//
//     connections        sessionId -> connection
//     entityConnections  entityId  -> Set<sessionId>
//
// `pushToEntity` iterates that Set. Nothing revalidates the session.
//
// ⚠️ SO THE OPEN QUESTION IS WHETHER AN EVICTED INSTANCE KEEPS RECEIVING PUSHES
// — dead to the server on the request path, live on the delivery path. That is
// the one-way break `BROKER-RELIABILITY.md` measured in claude-peers, where
// outbound succeeded from an id that could not be reached: a link where each
// side holds affirmative evidence it works.
//
// This file exists to answer it by measurement rather than by reading the code,
// because "the session row is gone" and "the socket is closed" are different
// facts and only one of them was implemented.
// ============================================================================

const TEST_HOST = '127.0.0.1';
const ACCOUNT = 'supersededpush@example.com';
const RECEIVER = `receiver@${ACCOUNT}`;
const SENDER = `sender@${ACCOUNT}`;

let serverHandle: ReturnType<typeof startServer>;
let BASE: string;
let pub: string;
let priv: string;

type Endpoint = '/entities/connect' | '/entities/authenticate' | '/messages/send';

async function post(path: Endpoint, body: unknown): Promise<{ status: number; data: any }> {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, data: await res.json().catch(() => null) };
}

async function authenticate(entityId: string, instanceId?: string) {
  const conn = await post('/entities/connect', { entity_id: entityId, public_key: pub });
  expect(conn.status).toBe(200);
  const signed = await createChallengeResponse(conn.data.nonce, priv);
  return post('/entities/authenticate', {
    entity_id: entityId,
    nonce: signed.nonce,
    signature: signed.signature,
    ...(instanceId ? { instance_id: instanceId } : {}),
  });
}

/** Open a real socket through the HTTP upgrade and collect what it receives. */
async function openSocket(entityId: string, sessionId: string) {
  const url = `${BASE.replace('http', 'ws')}/ws?entity_id=${encodeURIComponent(entityId)}&session_id=${sessionId}`;
  const ws = new WebSocket(url);
  const received: string[] = [];
  ws.onmessage = (e) => received.push(String(e.data));

  const opened = await new Promise<boolean>((resolve) => {
    const timer = setTimeout(() => resolve(false), 3000);
    ws.onopen = () => { clearTimeout(timer); resolve(true); };
    ws.onerror = () => { clearTimeout(timer); resolve(false); };
  });

  return { ws, received, opened };
}

beforeAll(async () => {
  const ctx = getDatabaseContext();
  ctx.db.prepare('INSERT OR IGNORE INTO accounts (id) VALUES (?)').run(ACCOUNT);

  const k = await generateKeyPair();
  pub = bufferToBase64(k.publicKey);
  priv = bufferToBase64(k.privateKey);

  const insert = ctx.db.prepare(
    `INSERT OR IGNORE INTO entities (id, account_id, type, public_key, capabilities)
     VALUES (?, ?, 'agent', ?, '{"can_send":true}')`
  );
  insert.run(RECEIVER, ACCOUNT, pub);
  insert.run(SENDER, ACCOUNT, pub);

  serverHandle = startServer({ port: 0, host: TEST_HOST });
  BASE = `http://${TEST_HOST}:${serverHandle.port}`;
});

afterAll(() => stopServer(serverHandle));

describe('⚠️ supersession and the push channel', () => {
  test('control: a LIVE socket receives a pushed message', async () => {
    // Establishes that the instrument can observe a delivery at all. Without
    // this, the assertion below passes against a test that never sees a push
    // for any reason — the wrong wiring, the wrong entity, a silent send
    // failure — and reports it as eviction working.
    const auth = await authenticate(RECEIVER, 'push-instance-live');
    const sock = await openSocket(RECEIVER, auth.data.session_id);
    expect(sock.opened).toBe(true);

    const senderAuth = await authenticate(SENDER);
    const sent = await post('/messages/send', {
      entity_id: SENDER,
      session_id: senderAuth.data.session_id,
      to_entity: RECEIVER,
      text: 'a message to a live socket',
    });
    expect(sent.status).toBe(201);

    await Bun.sleep(300);
    sock.ws.close();

    expect(sock.received.join(' ')).toContain('a message to a live socket');
  });

  test('⚠️ the socket is TOLD why before it closes', async () => {
    // ⚠️ MEASURED AS UNGUARDED FIRST. Suppressing the notice and closing
    // silently left every other test green — so the claim "it says why before
    // it closes", which the code asserts in a comment, had nothing behind it.
    //
    // The property is not cosmetic. A socket that simply drops is
    // indistinguishable from a network fault, and the client's reconnect logic
    // classifies network errors as TRANSIENT. A silent close would put the
    // evicted instance straight into the backoff loop that supersession exists
    // to stop — and two instances retrying at each other is the ping-pong
    // failure, which is worse than the duplication it resolves.
    const evicted = await authenticate(RECEIVER, 'push-instance-told-old');
    const sock = await openSocket(RECEIVER, evicted.data.session_id);
    expect(sock.opened).toBe(true);

    await authenticate(RECEIVER, 'push-instance-told-new');
    await Bun.sleep(300);

    const text = sock.received.join(' ');
    sock.ws.close();

    expect(text).toMatch(/superseded/i);
    // And what to DO, because a terminal notice that omits it is a client that
    // reconnects anyway.
    expect(text).toMatch(/should not reconnect/i);
  });

  test('⚠️ a SUPERSEDED instance must not keep receiving pushes', async () => {
    // THE QUESTION. The evicted instance's session is invalid — its next HTTP
    // request answers 401 — but its socket was validated once, at connect, and
    // lives in an in-memory map that nothing re-checks.
    const evicted = await authenticate(RECEIVER, 'push-instance-old');
    const sock = await openSocket(RECEIVER, evicted.data.session_id);
    expect(sock.opened).toBe(true);

    // A different instance takes the identity.
    const taking = await authenticate(RECEIVER, 'push-instance-new');
    expect(taking.status).toBe(200);
    expect(taking.data.superseded).toBeGreaterThan(0);

    sock.received.length = 0; // ignore anything from before the eviction

    const senderAuth = await authenticate(SENDER);
    const sent = await post('/messages/send', {
      entity_id: SENDER,
      session_id: senderAuth.data.session_id,
      to_entity: RECEIVER,
      text: 'a message after the eviction',
    });
    expect(sent.status).toBe(201);

    await Bun.sleep(300);
    sock.ws.close();

    // ⚠️ If this fails, eviction stops REQUESTS and not DELIVERY: the evicted
    // process is dead to the server and live on the push channel, which is the
    // one-way break BROKER-RELIABILITY.md measured in a different system.
    expect(sock.received.join(' ')).not.toContain('a message after the eviction');
  });
});
