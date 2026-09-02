import { test, expect, describe, beforeAll } from 'bun:test';
import { getDatabaseContext } from '../index';
import type { DatabaseContext } from '../transaction';

// ============================================================================
// Work with an owner, so "nobody is doing this" is a QUERY.
//
// THE MEASURED HARM: a lane killed mid-task leaves work that HAD an owner and
// LOST them, and nothing detects it. An architect's own words: "it looks
// assigned in my head and is assigned to nobody." Fuel PR #29 sat written,
// standing-approved and unmerged for FOUR DAYS because its author was killed
// and the task was never re-queued. One restart produced the failure three ways
// at once across the portfolio.
//
// WHY NOTHING FAM ALREADY HAS ANSWERS THIS. `queue_empty`, `last_state_change`
// and session liveness read as a triple answer "is this AGENT stalled?". An
// orphaned task is a different object: it is about the WORK, and the work is
// invisible to every agent-level signal. #29 would not have been caught by any
// of them.
//
// FAM MUST NOT LEARN WHAT THE WORK IS. A task carries an opaque title and an
// opaque external ref; the core never parses either. Same discipline as the
// context bag: it carries and compares, it does not interpret.
//
// UNATTENDED IS DERIVED, NEVER STORED. A stored flag goes stale the moment an
// owner reconnects — the same reason context collisions are computed at read
// time rather than written.
// ============================================================================

const ACCOUNT = 'tasks@example.com';
const OTHER = 'tasks-other@example.com';
const OWNER = `owner@${ACCOUNT}`;
const ABSENT = `absent@${ACCOUNT}`;
const DOOMED = `doomed@${ACCOUNT}`;
const FOREIGN = `f@${OTHER}`;

let ctx: DatabaseContext;

beforeAll(() => {
  ctx = getDatabaseContext();
  for (const a of [ACCOUNT, OTHER]) {
    ctx.db.prepare('INSERT OR IGNORE INTO accounts (id) VALUES (?)').run(a);
  }
  for (const [id, acct] of [
    [OWNER, ACCOUNT], [ABSENT, ACCOUNT], [DOOMED, ACCOUNT], [FOREIGN, OTHER],
  ] as const) {
    ctx.db
      .prepare(
        `INSERT OR IGNORE INTO entities (id, account_id, type, public_key, capabilities)
         VALUES (?, ?, 'agent', 'pk', '{"can_send":true}')`
      )
      .run(id, acct);
  }
  // OWNER is connected; ABSENT deliberately never is.
  ctx.sessions.create(OWNER);
});

describe('a task records who owns it', () => {
  test('created with an owner', () => {
    const t = ctx.tasks.create(ACCOUNT, { title: 'merge #29', owner_entity_id: OWNER });
    expect(t.owner_entity_id).toBe(OWNER);
    expect(t.status).toBe('open');
  });

  test('created without one — unassigned is a real state, not a defect', () => {
    const t = ctx.tasks.create(ACCOUNT, { title: 'nobody has this yet' });
    expect(t.owner_entity_id).toBeNull();
  });

  test('an opaque external ref rides along and is never parsed', () => {
    const t = ctx.tasks.create(ACCOUNT, { title: 'x', ref: 'fuel#29' });
    expect(t.ref).toBe('fuel#29');
  });

  test('ownership can be handed over', () => {
    const t = ctx.tasks.create(ACCOUNT, { title: 'reassign me', owner_entity_id: ABSENT });
    ctx.tasks.assign(t.id, OWNER);
    expect(ctx.tasks.getById(t.id)!.owner_entity_id).toBe(OWNER);
  });
});

describe('unattended work is found, and the two causes are kept apart', () => {
  test('an open task whose owner is not connected is reported', () => {
    const t = ctx.tasks.create(ACCOUNT, { title: 'author was killed', owner_entity_id: ABSENT });
    const found = ctx.tasks.findUnattended(ACCOUNT).find(u => u.task.id === t.id);

    expect(found).toBeDefined();
    expect(found!.reason).toBe('owner_offline');
  });

  test('an open task with NO owner is reported for a different reason', () => {
    const t = ctx.tasks.create(ACCOUNT, { title: 'never allocated' });
    const found = ctx.tasks.findUnattended(ACCOUNT).find(u => u.task.id === t.id);

    expect(found).toBeDefined();
    // Collapsing these would be the whole mistake: "re-queue it" and "assign it
    // to somebody" are different actions.
    expect(found!.reason).toBe('unowned');
  });

  test('an open task with a CONNECTED owner is not reported', () => {
    const t = ctx.tasks.create(ACCOUNT, { title: 'in hand', owner_entity_id: OWNER });
    expect(ctx.tasks.findUnattended(ACCOUNT).some(u => u.task.id === t.id)).toBe(false);
  });

  test('a CLOSED task with an absent owner is not reported', () => {
    const t = ctx.tasks.create(ACCOUNT, { title: 'finished', owner_entity_id: ABSENT });
    ctx.tasks.close(t.id, 'done');
    // Work that is done cannot be orphaned. Reporting it would train readers to
    // ignore the list, which is how a real orphan gets missed.
    expect(ctx.tasks.findUnattended(ACCOUNT).some(u => u.task.id === t.id)).toBe(false);
  });

  // Surface the age; do not decide the threshold. An owner offline for four
  // minutes and one offline for four days are both "not connected", and only
  // the reader knows which matters.
  test('it reports how long the owner has been gone rather than judging it', () => {
    const t = ctx.tasks.create(ACCOUNT, { title: 'aging', owner_entity_id: ABSENT });
    const found = ctx.tasks.findUnattended(ACCOUNT).find(u => u.task.id === t.id)!;
    expect('owner_last_seen' in found).toBe(true);
  });
});

describe('the work outlives its owner', () => {
  // Deleting the entity must NOT delete the task. Destroying work when its
  // owner is removed is the exact failure this table exists to prevent — the
  // task has to survive, visibly unowned, so somebody can re-queue it.
  test('deleting the owner entity orphans the task rather than destroying it', () => {
    const t = ctx.tasks.create(ACCOUNT, { title: 'survives its author', owner_entity_id: DOOMED });

    ctx.db.prepare('DELETE FROM entities WHERE id = ?').run(DOOMED);

    const after = ctx.tasks.getById(t.id);
    expect(after).not.toBeNull();
    expect(after!.owner_entity_id).toBeNull();

    const found = ctx.tasks.findUnattended(ACCOUNT).find(u => u.task.id === t.id);
    expect(found!.reason).toBe('unowned');
  });
});

describe('tasks do not cross an account boundary', () => {
  test('another account sees none of these', () => {
    ctx.tasks.create(ACCOUNT, { title: 'mine', owner_entity_id: ABSENT });
    expect(ctx.tasks.findUnattended(OTHER)).toEqual([]);
  });

  test('and its own unattended work is its own', () => {
    const t = ctx.tasks.create(OTHER, { title: 'theirs', owner_entity_id: FOREIGN });
    const found = ctx.tasks.findUnattended(OTHER).find(u => u.task.id === t.id);
    expect(found).toBeDefined();
    expect(ctx.tasks.findUnattended(ACCOUNT).some(u => u.task.id === t.id)).toBe(false);
  });
});
