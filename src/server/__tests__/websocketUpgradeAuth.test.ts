import { test, expect, describe, beforeAll, afterAll } from 'bun:test';
import { startServer, stopServer } from '../http';
import { getDatabaseContext } from '../../db';

// ============================================================================
// ⚠️ THE WEBSOCKET UPGRADE'S SESSION-TO-ENTITY BINDING, WHICH NOTHING TESTED.
//
//     src/server/http.ts
//     if (!session || session.entity_id !== entityId) {
//       return new Response('Invalid session', { status: 401 });
//     }
//
// Measured: deleting `|| session.entity_id !== entityId` — so ANY VALID SESSION
// ID CAN OPEN A WEBSOCKET AS ANY ENTITY, then receive that entity's pushes and
// send as them — left 787 pass, 0 fail.
//
// ⚠️ ITS HTTP TWIN IS TESTED. `requireEntitySession` refuses a body-supplied
// `entity_id` that disagrees with the session, and three tests cover it,
// including one named "cannot act as an entity the session does not own".
// SAME RULE, TWO IMPLEMENTATIONS, ONE OF THEM GUARDED. `CLAUDE.md` warns that a
// second session-authentication implementation is an answer waiting to drift —
// the drift here is not in the BEHAVIOUR, it is in the COVERAGE, and no reading
// of either file reveals it.
//
// ⚠️ AND THE REPO'S OWN ANTI-REGRESSION DEVICE CANNOT SEE THIS PATH.
// `integration.test.ts` enumerates every registered route and fails if an
// entity-scoped one answers anything but 401 unauthenticated, "so a new route
// cannot default into being untested". A WebSocket upgrade is not a registered
// route and is not in that enumeration. The check designed to make untested
// auth impossible has a domain, and this is outside it.
//
// The existing WebSocket tests call `wsManager.handleConnection(...)` directly,
// which is the right shape for testing frame handling and the reason this guard
// was never reached: it lives in the HTTP upgrade, above the manager.
// ============================================================================

const TEST_HOST = '127.0.0.1';
const ACCOUNT = 'wsupgrade@example.com';
const ALICE = `alice@${ACCOUNT}`;
const BOB = `bob@${ACCOUNT}`;

let serverHandle: ReturnType<typeof startServer>;
let BASE: string;
let aliceSession: string;
let bobSession: string;

/**
 * The upgrade handler answers BEFORE `server.upgrade` is reached, so a plain GET
 * exercises the guard exactly as a real client would and reads its status
 * directly. A refused upgrade over a real socket surfaces only as "the
 * connection closed", which cannot distinguish 401 from a crash.
 */
async function upgradeStatus(query: string): Promise<number> {
  const res = await fetch(`${BASE}/ws?${query}`);
  return res.status;
}

beforeAll(async () => {
  const ctx = getDatabaseContext();
  ctx.db.prepare('INSERT OR IGNORE INTO accounts (id) VALUES (?)').run(ACCOUNT);

  for (const id of [ALICE, BOB]) {
    ctx.db
      .prepare(
        `INSERT OR IGNORE INTO entities (id, account_id, type, public_key, capabilities)
         VALUES (?, ?, 'agent', 'pk', '{"can_send":true}')`
      )
      .run(id, ACCOUNT);
  }

  aliceSession = ctx.sessions.create(ALICE).id;
  bobSession = ctx.sessions.create(BOB).id;

  // Ephemeral port, for the reason `integration.test.ts` documents: a fixed port
  // collides with the PREVIOUS run's client sockets in TIME_WAIT, the bind
  // throws inside `beforeAll`, and the whole file's tests vanish from the count.
  serverHandle = startServer({ port: 0, host: TEST_HOST });
  BASE = `http://${TEST_HOST}:${serverHandle.port}`;
});

afterAll(() => stopServer(serverHandle));

describe('⚠️ /ws — a session may only speak as its OWN entity', () => {
  test("a VALID session cannot open a socket as a DIFFERENT entity", async () => {
    // THE UNGUARDED RULE. Alice's session is real and unexpired; only the entity
    // it names is wrong. Both halves of the guard's condition are satisfiable
    // independently and only the other one was reachable by any test.
    expect(await upgradeStatus(`entity_id=${BOB}&session_id=${aliceSession}`)).toBe(401);
  });

  test('and not in the other direction either', async () => {
    // Bob's session naming Alice. Stated separately because "A cannot be B" and
    // "B cannot be A" are one rule only if the check is symmetric, and reading
    // it as symmetric is an assumption about the code rather than a measurement.
    expect(await upgradeStatus(`entity_id=${ALICE}&session_id=${bobSession}`)).toBe(401);
  });

  test('a session id that names nothing is refused — the half that WAS reachable', async () => {
    // Kept as its own test so the two halves of the compound condition are two
    // visible cases. They shared one line, and that is how the second went
    // unmeasured.
    expect(
      await upgradeStatus(`entity_id=${ALICE}&session_id=00000000-0000-4000-8000-000000000000`)
    ).toBe(401);
  });

  test('control: the matching pair is NOT refused', async () => {
    // ⚠️ WITHOUT THIS, EVERY ASSERTION ABOVE PASSES AGAINST AN UPGRADE HANDLER
    // THAT REFUSES EVERYTHING — a different defect wearing the same green.
    //
    // A plain GET carries no Upgrade header, so `server.upgrade` declines and
    // the handler returns 500. That is not a passing WebSocket handshake and is
    // not asserted as one; it is asserted as NOT 401 — the guard let this pair
    // through. The next test does the real handshake.
    const status = await upgradeStatus(`entity_id=${ALICE}&session_id=${aliceSession}`);
    expect(status).not.toBe(401);
    expect(status).toBe(500);
  });

  test('control: the matching pair really does open a socket', async () => {
    // The honest positive control: a real handshake, so "not 401" above is
    // backed by a connection that actually works rather than by a status code
    // that merely differs.
    const ws = new WebSocket(`${BASE.replace('http', 'ws')}/ws?entity_id=${ALICE}&session_id=${aliceSession}`);

    const opened = await new Promise<boolean>((resolve) => {
      const timer = setTimeout(() => resolve(false), 2000);
      ws.onopen = () => {
        clearTimeout(timer);
        resolve(true);
      };
      ws.onerror = () => {
        clearTimeout(timer);
        resolve(false);
      };
    });
    ws.close();

    expect(opened).toBe(true);
  });
});
