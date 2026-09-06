import { test, expect, describe, beforeAll, afterAll } from 'bun:test';
import { startServer, stopServer } from '../http';
import { getDatabaseContext } from '../../db';
import { hashToken } from '../../auth/oauth';

// ============================================================================
// ⚠️ WHO A RULING'S NOTE MAY BE ATTRIBUTED TO — A GUARD WITH NO TEST.
//
//     src/server/routes/rulings.ts
//     if (recorded_by_entity) {
//       const recorder = ctx.entities.getById(recorded_by_entity);
//       if (!recorder || recorder.account_id !== accountId) {
//         throw new ForbiddenError('recorded_by_entity must be an entity in your account');
//       }
//     }
//
// Measured: deleting `|| recorder.account_id !== accountId` — so ONE ACCOUNT MAY
// SIGN ITS INTERPRETATION WITH ANOTHER ACCOUNT'S ENTITY — left 787 pass, 0 fail.
//
// ⚠️ AND THE HARM IS THE ONE THE REPOSITORY LAYER ALREADY ARGUES AGAINST IN
// PROSE. `ruling.ts` refuses a note with no `recorded_by_entity` because "an
// unattributed reading beside an attributed quote is how the derived thing ends
// up being read as the granter's". That rule makes attribution MANDATORY; this
// one makes it TRUE. Only the first had a test, so the field was guaranteed to
// be present and not guaranteed to be honest — and a false attribution is worse
// than an absent one, because it is the form a reader trusts.
//
// The repository's own tests exercise `recorded_by_entity` at the DB layer,
// where no account check exists to test. That is what made the route's gap
// invisible: a green primitive next to an ungated caller.
// ============================================================================

const TEST_HOST = '127.0.0.1';
const SECRET = process.env.FAM_SERVER_SECRET!;

const GRANTER = 'ruling-granter@example.com';
const OTHER = 'ruling-other@example.com';
const GRANTEE = 'ruling-grantee@example.com';

const GRANTER_TOKEN = 'ruling-granter-token';
const MY_ENTITY = `scribe@${GRANTER}`;
const THEIR_ENTITY = `scribe@${OTHER}`;

let serverHandle: ReturnType<typeof startServer>;
let BASE: string;

async function recordRuling(fields: Record<string, unknown>) {
  const res = await fetch(`${BASE}/admin/api/rulings`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ account_token: GRANTER_TOKEN, ...fields }),
  });
  return { status: res.status, data: (await res.json().catch(() => null)) as any };
}

/** Rulings this account has recorded, newest first is irrelevant — we count. */
function recordedBy(entityId: string): number {
  return getDatabaseContext()
    .rulings.listByGranter(GRANTER)
    .filter((r) => r.recorded_by_entity === entityId).length;
}

beforeAll(async () => {
  const ctx = getDatabaseContext();
  for (const id of [GRANTER, OTHER, GRANTEE]) {
    ctx.db.prepare('INSERT OR IGNORE INTO accounts (id) VALUES (?)').run(id);
  }

  ctx.db
    .prepare(
      `INSERT OR IGNORE INTO authorizations (id, account_id, server_id, token_hash)
       VALUES (?, ?, 'local', ?)`
    )
    .run('ruling-auth-1', GRANTER, await hashToken(GRANTER_TOKEN, SECRET));

  const entity = ctx.db.prepare(
    `INSERT OR IGNORE INTO entities (id, account_id, type, public_key, capabilities)
     VALUES (?, ?, 'agent', 'pk', '{"can_send":true}')`
  );
  entity.run(MY_ENTITY, GRANTER);
  entity.run(THEIR_ENTITY, OTHER);

  // Ephemeral port, for the reason `integration.test.ts` documents.
  serverHandle = startServer({ port: 0, host: TEST_HOST });
  BASE = `http://${TEST_HOST}:${serverHandle.port}`;
});

afterAll(() => stopServer(serverHandle));

describe("⚠️ a note may only be attributed to an entity you own", () => {
  test("attributing to ANOTHER ACCOUNT's entity is REFUSED", async () => {
    // THE UNGUARDED RULE. The entity exists and is well-formed; the only thing
    // wrong with it is whose it is. That is the half the compound condition
    // covered and no test reached.
    const { status } = await recordRuling({
      grantee_account_id: GRANTEE,
      scope: 'test/scope',
      body: 'The granter said this.',
      note: 'and this is my reading of it',
      recorded_by_entity: THEIR_ENTITY,
    });

    expect(status).toBe(403);
    // The row, not just the status: a refusal that had already written one
    // would leave a ruling signed by an entity its granter does not own, which
    // is the entire harm.
    expect(recordedBy(THEIR_ENTITY)).toBe(0);
  });

  test('attributing to an entity that does not exist is REFUSED — the half that WAS reachable', async () => {
    // Written as its own test so the two halves of the condition are two
    // visible cases. They shared one line, and that is how the second went
    // unmeasured here and in two other routes.
    const { status } = await recordRuling({
      grantee_account_id: GRANTEE,
      scope: 'test/scope',
      body: 'The granter said this.',
      note: 'signed by nobody',
      recorded_by_entity: `ghost@${GRANTER}`,
    });

    expect(status).toBe(403);
  });

  test('control: attributing to your OWN entity SUCCEEDS', async () => {
    // ⚠️ Without this, both tests above pass against a route that refuses every
    // ruling carrying a note — a different defect wearing the same green.
    const { status, data } = await recordRuling({
      grantee_account_id: GRANTEE,
      scope: 'test/scope',
      body: 'The granter said this.',
      note: 'and this is my reading of it',
      recorded_by_entity: MY_ENTITY,
    });

    expect(status).toBe(201);
    expect(data.ruling.recorded_by_entity).toBe(MY_ENTITY);
    expect(recordedBy(MY_ENTITY)).toBe(1);
  });

  test('control: a ruling with NO note and no recorder is untouched by this guard', async () => {
    // The guard is inside `if (recorded_by_entity)`. Without this, a version
    // that refused every ruling would still look correct beside the three tests
    // above, all of which supply a recorder.
    const { status } = await recordRuling({
      grantee_account_id: GRANTEE,
      scope: 'test/scope',
      body: 'A ruling with no interpretation attached.',
    });

    expect(status).toBe(201);
  });
});
