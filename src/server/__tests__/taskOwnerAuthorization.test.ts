import { test, expect, describe, beforeAll, afterAll } from 'bun:test';
import { startServer, stopServer } from '../http';
import { getDatabaseContext } from '../../db';

// ============================================================================
// ⚠️ `assertMayOwn` — THE TASK API'S ONLY LINK TO THE PERMISSION MATRIX, AND
// NOTHING TESTED THE PERMISSION HALF OF IT.
//
//     src/server/routes/tasks.ts
//     if (!actor || !owner || !permissions.canDirectMessage(actor, owner)) {
//       throw new ForbiddenError(`Cannot assign to ${ownerId}: ...`);
//     }
//
// Measured: deleting `|| !permissions.canDirectMessage(actor, owner)` — so an
// actor may assign work to ANY entity that exists, including one in an account
// that has granted them nothing — left 787 pass, 0 fail.
//
// ⚠️ AND `canDirectMessage` ITSELF IS WELL TESTED, at the PermissionChecker
// level, in `src/db/__tests__/pending-grants.test.ts`. That is what made this
// invisible: the primitive is green, so the ROUTE looks covered. A tested
// primitive says nothing about whether a caller calls it.
//
// The guard is shared by /tasks/create and /tasks/assign, so both are exercised
// here — a rule enforced on one entry point and not the other is the same
// divergence this repo already decided against for HTTP versus WebSocket send.
//
// ⚠️ NOTE WHAT IS **NOT** CLAIMED. This file does not test that a GRANT makes a
// cross-account assignment succeed; it tests that the ABSENCE of one refuses.
// The positive control is same-account, which is a different branch of
// `canDirectMessage` (default-allow) than the cross-account one (grant
// required). Naming that keeps the control honest about what it controls for.
// ============================================================================

const TEST_HOST = '127.0.0.1';
const MINE = 'taskowner-mine@example.com';
const THEIRS = 'taskowner-theirs@example.com';

const ACTOR = `actor@${MINE}`;
const COLLEAGUE = `colleague@${MINE}`;
const STRANGER = `stranger@${THEIRS}`;

let serverHandle: ReturnType<typeof startServer>;
let BASE: string;

type Endpoint = '/tasks/create' | '/tasks/assign';

async function as(
  entityId: string,
  path: Endpoint,
  body: Record<string, unknown>
): Promise<{ status: number; data: any }> {
  const session = getDatabaseContext().sessions.create(entityId).id;
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ entity_id: entityId, session_id: session, ...body }),
  });
  return { status: res.status, data: await res.json().catch(() => null) };
}

beforeAll(async () => {
  const ctx = getDatabaseContext();
  for (const id of [MINE, THEIRS]) {
    ctx.db.prepare('INSERT OR IGNORE INTO accounts (id) VALUES (?)').run(id);
  }

  const entity = ctx.db.prepare(
    `INSERT OR IGNORE INTO entities (id, account_id, type, public_key, capabilities)
     VALUES (?, ?, 'agent', 'pk', '{"can_send":true}')`
  );
  entity.run(ACTOR, MINE);
  entity.run(COLLEAGUE, MINE);
  entity.run(STRANGER, THEIRS);
  // No grant from THEIRS to MINE, deliberately. That absence IS the subject.

  // Ephemeral port, for the reason `integration.test.ts` documents.
  serverHandle = startServer({ port: 0, host: TEST_HOST });
  BASE = `http://${TEST_HOST}:${serverHandle.port}`;
});

afterAll(() => stopServer(serverHandle));

describe('⚠️ /tasks/create — you may not assign work to someone you may not message', () => {
  test('assigning to an entity in an account that granted you nothing is REFUSED', async () => {
    const { status } = await as(ACTOR, '/tasks/create', {
      title: 'work for a stranger',
      owner_entity_id: STRANGER,
    });

    expect(status).toBe(403);
    // No task, not merely no success: a refusal that had already written the row
    // would satisfy a status assertion and leave the assignment standing.
    const tasks = getDatabaseContext().tasks.listByAccount(MINE);
    expect(tasks.some((t) => t.owner_entity_id === STRANGER)).toBe(false);
  });

  test('control: assigning to a colleague in your OWN account SUCCEEDS', async () => {
    // ⚠️ Without this, the test above passes against a route that refuses every
    // assignment — a different defect wearing the same green.
    const { status, data } = await as(ACTOR, '/tasks/create', {
      title: 'work for a colleague',
      owner_entity_id: COLLEAGUE,
    });

    expect(status).toBe(201);
    expect(data.task.owner_entity_id).toBe(COLLEAGUE);
  });

  test('control: an unassigned task is not refused either', async () => {
    // `owner_entity_id` is optional and the guard must not fire when it is
    // absent. Without this, a guard that refused every CREATE would still look
    // correct beside the two tests above.
    const { status } = await as(ACTOR, '/tasks/create', { title: 'work for nobody' });
    expect(status).toBe(201);
  });
});

describe('⚠️ /tasks/assign — the same rule on the other entry point', () => {
  let taskId: string;

  test('setup: a task exists in the actor\'s account', async () => {
    const { status, data } = await as(ACTOR, '/tasks/create', { title: 'to be handed over' });
    expect(status).toBe(201);
    taskId = data.task.id;
  });

  test('handing it to an entity you may not message is REFUSED', async () => {
    const { status } = await as(ACTOR, '/tasks/assign', {
      task_id: taskId,
      owner_entity_id: STRANGER,
    });

    expect(status).toBe(403);
    expect(getDatabaseContext().tasks.getById(taskId)?.owner_entity_id).toBeNull();
  });

  test('control: handing it to a colleague SUCCEEDS', async () => {
    const { status } = await as(ACTOR, '/tasks/assign', {
      task_id: taskId,
      owner_entity_id: COLLEAGUE,
    });

    expect(status).toBe(200);
    expect(getDatabaseContext().tasks.getById(taskId)?.owner_entity_id).toBe(COLLEAGUE);
  });
});
