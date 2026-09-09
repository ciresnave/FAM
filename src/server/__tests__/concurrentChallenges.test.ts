import { test, expect, describe, beforeAll, afterAll } from 'bun:test';
import { startServer, stopServer } from '../http';
import { getDatabaseContext } from '../../db';
import { generateKeyPair, bufferToBase64 } from '../../crypto/keys';
import { createChallengeResponse } from '../../crypto/challenge';

// ============================================================================
// ⚠️ TWO OVERLAPPING connect -> authenticate EXCHANGES FOR ONE ENTITY MADE BOTH
// FAIL, AND TOLD BOTH CALLERS SOMETHING FALSE.
//
// Measured at `43e2498f`, before the fix in this commit:
//
//     connect A                     200, nonce A
//     connect B                     200, nonce B   (replaced A's row)
//     authenticate A (correct sig)  401  "Invalid signature"
//     authenticate B (correct sig)  401  "Challenge has expired"
//     CONTROL: solo connect+auth    200
//
// `challenges.entity_id` was a PRIMARY KEY written with INSERT OR REPLACE, and
// `/entities/authenticate` CONSUMES the row. So B's connect overwrote A's
// nonce; A consumed the only row — carrying B's nonce, so A's valid signature
// did not verify; and B then found nothing.
//
// ⚠️ NEITHER MESSAGE NAMED THE CAUSE, AND ONE POINTED AWAY FROM IT.
// "Invalid signature" is the message that sends an operator to check their key
// file, which is the one thing that was never wrong.
//
// ⚠️ AND IT WAS NOT A RACE. The two connects above are SEQUENTIAL. The window
// is the whole exchange, so an agent restarting while a previous instance still
// holds a session could lock itself out — and the MCP client classifies 401 as
// PERMANENT, so it does not ride it out. It stops and reports a key problem.
//
// ⚠️ THE FUNCTION THAT CAUSED IT DOCUMENTS ITSELF AS RACE-SAFE.
// `consumeChallenge` wraps its read-and-delete in a transaction "to prevent
// race conditions between concurrent authentications". That transaction is
// CORRECT and protects the wrong thing: it makes access to ONE row atomic, and
// the defect was that there could only ever BE one row. A guard can be right
// about its own invariant and still be built on the wrong model.
// ============================================================================

const TEST_HOST = '127.0.0.1';
const ACCOUNT = 'concurrentchal@example.com';
const ENTITY = `agent@${ACCOUNT}`;
const OTHER = `other@${ACCOUNT}`;

let serverHandle: ReturnType<typeof startServer>;
let BASE: string;
let pub: string;
let priv: string;
let otherPub: string;
let otherPriv: string;

/**
 * The two endpoints this file touches, as a closed set.
 *
 * ⚠️ THIS DOES NOT CLEAR CODACY'S `node-ssrf` FINDING ON THE `fetch` BELOW,
 * and saying so is the point. Measured on #43: the rule has instances repo-wide
 * on sibling test helpers that ALREADY use this exact form, so the check is
 * syntactic and the type is invisible to it.
 *
 * It earns its place anyway. A typo'd path becomes a compile error rather than
 * an expectation failure three assertions later — and it makes the PR's
 * disposition CHECKABLE: "only two literal paths reach this call" stops being
 * something I read off the call sites once and becomes something the compiler
 * enforces as call sites are added.
 */
type Endpoint = '/entities/connect' | '/entities/authenticate';

async function post(path: Endpoint, body: unknown): Promise<{ status: number; data: any }> {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, data: await res.json().catch(() => null) };
}

async function connect(entityId: string, publicKey: string): Promise<string> {
  const { status, data } = await post('/entities/connect', {
    entity_id: entityId,
    public_key: publicKey,
  });
  expect(status).toBe(200);
  return data.nonce as string;
}

async function authenticate(entityId: string, nonce: string, privateKey: string) {
  const signed = await createChallengeResponse(nonce, privateKey);
  return post('/entities/authenticate', {
    entity_id: entityId,
    nonce: signed.nonce,
    signature: signed.signature,
  });
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
  insert.run(ENTITY, ACCOUNT, pub);
  insert.run(OTHER, ACCOUNT, otherPub);

  // Ephemeral port, for the reason `integration.test.ts` documents.
  serverHandle = startServer({ port: 0, host: TEST_HOST });
  BASE = `http://${TEST_HOST}:${serverHandle.port}`;
});

afterAll(() => stopServer(serverHandle));

describe('⚠️ two instances of one entity may each authenticate', () => {
  test('BOTH overlapping exchanges succeed — neither consumes the other', async () => {
    // THE BUG. Two connects before either authenticates, then each redeems the
    // nonce IT was issued. Before the fix this produced 401 + 401.
    const nonceA = await connect(ENTITY, pub);
    const nonceB = await connect(ENTITY, pub);

    expect(nonceA).not.toBe(nonceB); // two connects really are two challenges

    const authA = await authenticate(ENTITY, nonceA, priv);
    const authB = await authenticate(ENTITY, nonceB, priv);

    expect(authA.status).toBe(200);
    expect(authB.status).toBe(200);

    // Two SESSIONS, not one reused. Multi-connection is a designed feature
    // (`websocket.ts` keeps entityId -> Set<sessionId>), so the fix must give
    // each exchange its own session rather than merely stop erroring.
    expect(authA.data.session_id).not.toBe(authB.data.session_id);
  });

  test('⚠️ the SECOND instance may authenticate FIRST — arrival order is not part of the contract', async () => {
    // ⚠️ THIS TEST EXISTS BECAUSE THE TEST ABOVE DID NOT PIN THE FIX.
    //
    // Mutation-tested: reverting `consumeChallenge` to look up by `entity_id`
    // ALONE — the original defect — left the test above at 6 pass, 0 fail. With
    // the composite key from migration 20 two rows coexist, so an entity-only
    // SELECT returns whichever row SQLite hands back, and in insertion order
    // that happens to be the right one for each caller. THE BEHAVIOUR WAS
    // CARRIED BY ROW ORDERING, NOT BY THE LOOKUP, and nothing said so.
    //
    // Redeeming the SECOND nonce FIRST removes the coincidence. An entity-only
    // lookup returns A's row, `verifyChallengeResponse` compares the stored
    // nonce to the presented one, they differ, and B is told "Invalid
    // signature" over a signature that is valid.
    const nonceA = await connect(ENTITY, pub);
    const nonceB = await connect(ENTITY, pub);

    const authB = await authenticate(ENTITY, nonceB, priv);
    expect(authB.status).toBe(200);

    // And A's challenge survived B's redemption rather than being consumed by it.
    const authA = await authenticate(ENTITY, nonceA, priv);
    expect(authA.status).toBe(200);
  });

  test('control: a single exchange still works', async () => {
    // Without this, the test above passes against a route that stopped
    // checking anything at all.
    const nonce = await connect(ENTITY, pub);
    const { status } = await authenticate(ENTITY, nonce, priv);
    expect(status).toBe(200);
  });
});

describe('⚠️ and the fix does not weaken what the challenge is for', () => {
  test('a nonce is still single-use', async () => {
    // The whole point of consuming: replaying a captured nonce must not
    // authenticate a second time.
    const nonce = await connect(ENTITY, pub);

    const first = await authenticate(ENTITY, nonce, priv);
    expect(first.status).toBe(200);

    const replay = await authenticate(ENTITY, nonce, priv);
    expect(replay.status).toBe(401);
  });

  test("one entity cannot redeem ANOTHER entity's nonce", async () => {
    // ⚠️ THE HAZARD INTRODUCED BY KEYING ON THE NONCE. Once a challenge is
    // looked up by nonce, a lookup that forgets to also match the entity would
    // let a holder of any valid nonce authenticate as whoever it was issued to.
    // The signature would still have to verify — but under the ATTACKER'S key,
    // because the route fetches the key of the entity NAMED IN THE BODY.
    const nonceForOther = await connect(OTHER, otherPub);

    const stolen = await authenticate(ENTITY, nonceForOther, priv);
    expect(stolen.status).toBe(401);

    // And the rightful owner can still use it afterwards — the failed attempt
    // must not have consumed it.
    const rightful = await authenticate(OTHER, nonceForOther, otherPriv);
    expect(rightful.status).toBe(200);
  });

  test('a nonce that was never issued is refused', async () => {
    const { status } = await authenticate(ENTITY, bufferToBase64(new Uint8Array(32)), priv);
    expect(status).toBe(401);
  });

  test('a wrong signature over a real nonce is still refused', async () => {
    // Control for the whole file: the route must still verify signatures, not
    // merely find rows.
    const nonce = await connect(ENTITY, pub);
    const { status } = await authenticate(ENTITY, nonce, otherPriv);
    expect(status).toBe(401);
  });
});
