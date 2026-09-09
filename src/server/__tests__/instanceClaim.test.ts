import { test, expect, describe, beforeAll, afterAll } from 'bun:test';
import { startServer, stopServer } from '../http';
import { getDatabaseContext } from '../../db';
import { generateKeyPair, bufferToBase64 } from '../../crypto/keys';
import { createChallengeResponse } from '../../crypto/challenge';

// ============================================================================
// ⚠️ WHICH RUNNING PROCESS HOLDS AN IDENTITY — THE QUESTION NO KEY CAN ANSWER.
//
// `DESIGN-INSTANCE-IDENTITY.md`: "A duplicated agent holds a copy of the key, so
// every cryptographic check answers 'same identity' — correctly, and uselessly."
// Challenge-response settles *are you 1234*. It cannot settle *are you the only
// 1234*, because that is a fact about processes and no key knows about
// processes.
//
// The discriminator is an INSTANCE ID: minted at process start, held in memory,
// never persisted. Two connections of one process present the same one; a
// restarted or cloned process mints a new one.
//
// ⚠️ AND THE HARD CONSTRAINT IS THAT MULTI-CONNECTION MUST SURVIVE. A CLI and an
// MCP adapter attached at once is the normal case — `websocket.ts` keeps
// `entityId -> Set<sessionId>` and fans pushes to all of them. Any mechanism
// that reduces to "one session per entity" breaks a working feature to fix a
// different problem. So the claim is attached to AUTHENTICATION, not to
// CONNECTION: same instance id is a connection, a different one is a claim.
//
// ⚠️ THE POLICY IS OPT-IN, DELIBERATELY, AND THAT IS HOW `type='human'` STAYS
// UNDECIDED. A person's entity legitimately runs on a phone and a laptop; under
// supersession the second would evict the first. That is a product call and it
// is CireSnave's. Sending no `instance_id` means no claim and no supersession,
// so a client that has not opted in is unaffected and NEITHER branch of the
// human/agent question is built. A mechanism that shipped with the likely answer
// baked in would have ANSWERED the question while APPEARING to defer it.
// ============================================================================

const TEST_HOST = '127.0.0.1';
const ACCOUNT = 'instanceclaim@example.com';
const AGENT = `agent@${ACCOUNT}`;
const OTHER = `other@${ACCOUNT}`;

let serverHandle: ReturnType<typeof startServer>;
let BASE: string;
let pub: string;
let priv: string;
let otherPub: string;
let otherPriv: string;

type Endpoint = '/entities/connect' | '/entities/authenticate' | '/entities/heartbeat';

async function post(path: Endpoint, body: unknown): Promise<{ status: number; data: any }> {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, data: await res.json().catch(() => null) };
}

/** Full connect -> authenticate, optionally claiming the identity for an instance. */
async function authenticate(
  entityId: string,
  privateKey: string,
  publicKey: string,
  instanceId?: string
): Promise<{ status: number; data: any }> {
  const conn = await post('/entities/connect', { entity_id: entityId, public_key: publicKey });
  expect(conn.status).toBe(200);
  const signed = await createChallengeResponse(conn.data.nonce, privateKey);
  return post('/entities/authenticate', {
    entity_id: entityId,
    nonce: signed.nonce,
    signature: signed.signature,
    ...(instanceId ? { instance_id: instanceId } : {}),
  });
}

/** Is this session still usable? The only thing supersession must actually do. */
async function sessionWorks(entityId: string, sessionId: string): Promise<boolean> {
  const { status } = await post('/entities/heartbeat', {
    entity_id: entityId,
    session_id: sessionId,
  });
  return status === 200;
}

beforeAll(async () => {
  const ctx = getDatabaseContext();
  ctx.db.prepare('INSERT OR IGNORE INTO accounts (id) VALUES (?)').run(ACCOUNT);

  const k = await generateKeyPair();
  pub = bufferToBase64(k.publicKey);
  priv = bufferToBase64(k.privateKey);
  const o = await generateKeyPair();
  otherPub = bufferToBase64(o.publicKey);
  otherPriv = bufferToBase64(o.privateKey);

  const insert = ctx.db.prepare(
    `INSERT OR IGNORE INTO entities (id, account_id, type, public_key, capabilities)
     VALUES (?, ?, 'agent', ?, '{"can_send":true}')`
  );
  insert.run(AGENT, ACCOUNT, pub);
  insert.run(OTHER, ACCOUNT, otherPub);

  // Ephemeral port, for the reason `integration.test.ts` documents.
  serverHandle = startServer({ port: 0, host: TEST_HOST });
  BASE = `http://${TEST_HOST}:${serverHandle.port}`;
});

afterAll(() => stopServer(serverHandle));

describe('⚠️ a second INSTANCE supersedes the first; a second CONNECTION does not', () => {
  test('same instance id twice: BOTH sessions keep working, and the generation does not move', async () => {
    // THE FEATURE THAT MUST SURVIVE. One process, two authentications — a CLI
    // and an MCP adapter, or a reconnect. Neither may evict the other.
    const first = await authenticate(AGENT, priv, pub, 'instance-alpha');
    const second = await authenticate(AGENT, priv, pub, 'instance-alpha');

    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    expect(first.data.session_id).not.toBe(second.data.session_id);

    expect(await sessionWorks(AGENT, first.data.session_id)).toBe(true);
    expect(await sessionWorks(AGENT, second.data.session_id)).toBe(true);

    // A connection is not a claim: the generation is unchanged between them.
    expect(second.data.generation).toBe(first.data.generation);
    expect(second.data.superseded).toBe(0);
  });

  test('⚠️ a DIFFERENT instance id supersedes: the older session stops working', async () => {
    const older = await authenticate(AGENT, priv, pub, 'instance-beta');
    expect(await sessionWorks(AGENT, older.data.session_id)).toBe(true);

    const newer = await authenticate(AGENT, priv, pub, 'instance-gamma');

    expect(newer.status).toBe(200);
    // The session, not just a status: supersession that left the old session
    // usable would be a claim nobody has to honour.
    expect(await sessionWorks(AGENT, older.data.session_id)).toBe(false);
    expect(await sessionWorks(AGENT, newer.data.session_id)).toBe(true);
  });

  test('the generation advances, so a stale claim is recognisable as stale', async () => {
    const a = await authenticate(AGENT, priv, pub, 'instance-delta');
    const b = await authenticate(AGENT, priv, pub, 'instance-epsilon');

    expect(typeof a.data.generation).toBe('number');
    expect(b.data.generation).toBeGreaterThan(a.data.generation);
    expect(b.data.superseded).toBeGreaterThan(0);
  });
});

describe('⚠️ a superseded session is told WHICH KIND OF DEAD it is', () => {
  // ⚠️ THIS IS WHY SUPERSESSION MARKS RATHER THAN DELETES.
  //
  // A deleted session is indistinguishable from one that expired, one whose id
  // was mistyped, and one that never existed — all of them answer "Invalid
  // session", which sends an operator to check credentials that were never
  // wrong. That is exactly the defect migration 20 fixed for `connect`, and
  // deleting here would have reintroduced it one table over, in the mechanism
  // written to resolve duplicate instances.

  test('the refusal NAMES supersession', async () => {
    const older = await authenticate(AGENT, priv, pub, 'instance-mu');
    await authenticate(AGENT, priv, pub, 'instance-nu');

    const { status, data } = await post('/entities/heartbeat', {
      entity_id: AGENT,
      session_id: older.data.session_id,
    });

    expect(status).toBe(401);
    expect(String(data.error)).toMatch(/superseded/i);
    // And it says what to DO, because a terminal failure that does not is a
    // client that reconnects into a ping-pong eviction.
    expect(String(data.error)).toMatch(/should not reconnect/i);
  });

  test('control: an UNKNOWN session id gets the generic message, so the distinction is real', async () => {
    // Without this, the assertion above passes against a route that returned
    // the supersession text for every bad session — which would be a different
    // defect wearing the same green, and a worse one, because it would tell
    // every mistyped id that it had been superseded.
    const { status, data } = await post('/entities/heartbeat', {
      entity_id: AGENT,
      session_id: '00000000-0000-4000-8000-000000000000',
    });

    expect(status).toBe(401);
    expect(String(data.error)).not.toMatch(/superseded/i);
  });

  test('⚠️ still 401, so the existing terminal-failure path still fires', async () => {
    // The status is load-bearing and is NOT free to change. `isPermanentFailure`
    // in the MCP client returns true for 401/403/404 and the reconnect loop
    // calls terminate() on it — which is the delivery mechanism this design
    // reuses instead of adding a second one. A superseded session answering
    // anything else would leave the old instance retrying forever.
    const older = await authenticate(AGENT, priv, pub, 'instance-xi');
    await authenticate(AGENT, priv, pub, 'instance-omicron');

    const { status } = await post('/entities/heartbeat', {
      entity_id: AGENT,
      session_id: older.data.session_id,
    });

    expect(status).toBe(401);
  });
});

describe('⚠️ opting out is the default, and it is how the human question stays open', () => {
  test('no instance_id: no claim, no supersession, and existing sessions survive', async () => {
    // BACKWARD COMPATIBILITY AND THE DEFERRAL IN ONE PROPERTY. A client that has
    // not opted in behaves exactly as before, so no policy about entity TYPE is
    // baked in anywhere.
    const held = await authenticate(AGENT, priv, pub, 'instance-zeta');
    expect(await sessionWorks(AGENT, held.data.session_id)).toBe(true);

    const anonymous = await authenticate(AGENT, priv, pub); // no instance_id
    expect(anonymous.status).toBe(200);

    // ⚠️ The claiming instance is NOT evicted by a non-claiming authentication.
    expect(await sessionWorks(AGENT, held.data.session_id)).toBe(true);
    expect(await sessionWorks(AGENT, anonymous.data.session_id)).toBe(true);
  });

  test('a non-claiming authentication is not itself superseded by a later claim', async () => {
    // The other direction: an opted-out session must not be collateral damage.
    const anonymous = await authenticate(AGENT, priv, pub);
    await authenticate(AGENT, priv, pub, 'instance-eta');

    expect(await sessionWorks(AGENT, anonymous.data.session_id)).toBe(true);
  });
});

describe('⚠️ a claim is scoped to ONE entity', () => {
  test("claiming one identity does not touch another entity's sessions", async () => {
    // Without this, a supersession implemented with a too-wide DELETE would pass
    // every test above while evicting the whole account.
    const bystander = await authenticate(OTHER, otherPriv, otherPub, 'instance-theta');
    expect(await sessionWorks(OTHER, bystander.data.session_id)).toBe(true);

    await authenticate(AGENT, priv, pub, 'instance-iota');
    await authenticate(AGENT, priv, pub, 'instance-kappa'); // a real supersession

    expect(await sessionWorks(OTHER, bystander.data.session_id)).toBe(true);
  });

  test('control: authentication still refuses a bad signature when claiming', async () => {
    // The claim must not become a way around the challenge. Without this, a
    // route that skipped verification whenever instance_id was present would
    // satisfy every test above.
    const conn = await post('/entities/connect', { entity_id: AGENT, public_key: pub });
    const signed = await createChallengeResponse(conn.data.nonce, otherPriv); // wrong key
    const { status } = await post('/entities/authenticate', {
      entity_id: AGENT,
      nonce: signed.nonce,
      signature: signed.signature,
      instance_id: 'instance-lambda',
    });

    expect(status).toBe(401);
  });
});
