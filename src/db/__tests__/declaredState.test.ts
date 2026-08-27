import { test, expect, describe, beforeAll } from 'bun:test';
import { getDatabaseContext } from '../index';
import type { DatabaseContext } from '../transaction';

// ============================================================================
// `queue_empty` and `last_state_change` are DECLARED state.
//
// They sit beside `availability` (the entity's stated intent), not beside
// `status` (derived from the connection). That is not a tidiness preference —
// it is the whole reason they are worth having.
//
// THE MEASUREMENT THAT MOTIVATED THEM. In one sweep of the claude-peers
// network, all 17 peers reported `Last seen` inside a 9.5-second window
// (15:51:04.309 to 15:51:13.784) while two agents had been idle for hours.
// `Last seen` is a process heartbeat: an agent doing nothing looks exactly
// like an agent working. So the new timestamp must move when an entity SAYS
// something changed, and must NOT move because it is still breathing.
//
// The discriminating test is therefore the negative one: a heartbeat must
// leave `last_state_change` alone. Without it this column silently becomes a
// second `last_seen` — it would still be populated, still look healthy, and
// still answer the wrong question.
//
// THE PAIR. An agent that dies mid-task never declares its queue empty, so
// `queue_empty = 0` means WORKING or DEAD with no third reading. Neither field
// alone can separate them:
//
//     queue_empty = 0  AND  last_state_change old   =>  stalled
//     queue_empty = 0  AND  last_state_change fresh =>  working
//
// And `queue_empty` is NULLABLE on purpose. NULL means "never declared", which
// is a different claim from "declared not-empty" — collapsing them would make
// every entity that has never spoken look busy.
// ============================================================================

const ACCOUNT = 'declared@example.com';
const AGENT = `worker@${ACCOUNT}`;
const QUIET = `quiet@${ACCOUNT}`;

let ctx: DatabaseContext;

beforeAll(() => {
  ctx = getDatabaseContext();
  ctx.db.prepare('INSERT OR IGNORE INTO accounts (id) VALUES (?)').run(ACCOUNT);
  for (const id of [AGENT, QUIET]) {
    ctx.db
      .prepare(
        `INSERT OR IGNORE INTO entities (id, account_id, type, public_key, capabilities)
         VALUES (?, ?, 'agent', 'pk', '{"can_send":true}')`
      )
      .run(id, ACCOUNT);
  }
});

function read(id: string): { queue_empty: number | null; last_state_change: string | null } {
  return ctx.db
    .prepare('SELECT queue_empty, last_state_change FROM entities WHERE id = ?')
    .get(id) as any;
}

describe('queue_empty distinguishes never-declared from declared', () => {
  test('a new entity has NOT declared, which is not the same as busy', () => {
    expect(read(QUIET).queue_empty).toBeNull();
  });

  test('declaring empty and declaring not-empty are both recorded', () => {
    ctx.entities.updateQueueEmpty(AGENT, true);
    expect(read(AGENT).queue_empty).toBe(1);

    ctx.entities.updateQueueEmpty(AGENT, false);
    expect(read(AGENT).queue_empty).toBe(0);
  });
});

describe('last_state_change tracks DECLARATIONS, not liveness', () => {
  test('declaring queue state stamps it', () => {
    ctx.db.prepare('UPDATE entities SET last_state_change = NULL WHERE id = ?').run(AGENT);
    ctx.entities.updateQueueEmpty(AGENT, true);
    expect(read(AGENT).last_state_change).not.toBeNull();
  });

  test('declaring availability stamps it', () => {
    ctx.db.prepare('UPDATE entities SET last_state_change = NULL WHERE id = ?').run(AGENT);
    ctx.entities.updateAvailability(AGENT, 'unavailable');
    expect(read(AGENT).last_state_change).not.toBeNull();
  });

  // THE DISCRIMINATOR. If this fails, the column is a second `last_seen` and
  // every reading built on it is wrong in the direction that looks healthy.
  test('a HEARTBEAT does not move it', () => {
    ctx.entities.updateQueueEmpty(AGENT, false);
    const stamped = read(AGENT).last_state_change;

    ctx.db
      .prepare("UPDATE entities SET last_state_change = datetime('now', '-3 hours') WHERE id = ?")
      .run(AGENT);
    const aged = read(AGENT).last_state_change;

    const session = ctx.sessions.create(AGENT);
    ctx.sessions.updateHeartbeat(session.id);

    expect(read(AGENT).last_state_change).toBe(aged!);
    expect(read(AGENT).last_state_change).not.toBe(stamped!);
  });

  // Status is connection-derived, so it is not a declaration either.
  test('a STATUS change does not move it', () => {
    ctx.db
      .prepare("UPDATE entities SET last_state_change = datetime('now', '-3 hours') WHERE id = ?")
      .run(AGENT);
    const aged = read(AGENT).last_state_change;

    ctx.entities.updateStatus(AGENT, 'online');

    expect(read(AGENT).last_state_change).toBe(aged!);
  });
});

describe('it records a CHANGE, not a declaration', () => {
  // The column is named for a change. If re-stating the same value refreshed
  // it, an agent looping on one state would look perpetually fresh — which is
  // the heartbeat failure this column exists to avoid, reintroduced through the
  // front door.
  test('re-declaring the SAME value leaves the timestamp alone', () => {
    ctx.entities.updateQueueEmpty(AGENT, false);
    ctx.db
      .prepare("UPDATE entities SET last_state_change = datetime('now', '-4 hours') WHERE id = ?")
      .run(AGENT);
    const aged = read(AGENT).last_state_change;

    ctx.entities.updateQueueEmpty(AGENT, false); // same value again

    expect(read(AGENT).last_state_change).toBe(aged!);
  });

  test('declaring a DIFFERENT value moves it', () => {
    ctx.db
      .prepare("UPDATE entities SET last_state_change = datetime('now', '-4 hours') WHERE id = ?")
      .run(AGENT);
    const aged = read(AGENT).last_state_change;

    ctx.entities.updateQueueEmpty(AGENT, true); // flipped

    expect(read(AGENT).last_state_change).not.toBe(aged!);
  });

  // First declaration from NULL is a change, not a no-op. Without this, an
  // entity's very first statement about itself would be unstamped.
  test('the FIRST declaration counts as a change', () => {
    ctx.entities.updateQueueEmpty(QUIET, false);
    expect(read(QUIET).last_state_change).not.toBeNull();
  });
});

describe('separating a long task from a dead agent needs the heartbeat too', () => {
  // The framing this shipped under was "the pair discriminates". It does not,
  // quite. queue_empty=0 with an old timestamp is BOTH a long-running task and
  // an agent that died mid-task — an agent working steadily on one thing has
  // not changed state, so its timestamp is legitimately old.
  //
  // What separates those two is liveness, which is exactly what
  // last_state_change refuses to encode. So the reading is a TRIPLE:
  //
  //   fresh timestamp                      -> working, changing
  //   old timestamp + live session         -> one long task
  //   old timestamp + no live session      -> died mid-task
  //
  // Recorded as a test rather than a comment because the two-field version is
  // the intuitive one and will be re-derived by whoever reads the columns next.
  test('queue_empty plus an old timestamp does NOT distinguish them', () => {
    ctx.entities.updateQueueEmpty(AGENT, false);
    ctx.db
      .prepare("UPDATE entities SET last_state_change = datetime('now', '-6 hours') WHERE id = ?")
      .run(AGENT);

    const longTask = read(AGENT);
    const dead = read(AGENT);

    // Identical on both new columns. Nothing here can tell them apart.
    expect(longTask.queue_empty).toBe(dead.queue_empty!);
    expect(longTask.last_state_change).toBe(dead.last_state_change!);
  });

  test('a live session is what separates them', () => {
    ctx.sessions.deleteByEntityId(AGENT);
    expect(ctx.sessions.isActive(AGENT)).toBe(false); // reads as died mid-task

    const s = ctx.sessions.create(AGENT);
    ctx.sessions.updateHeartbeat(s.id);
    expect(ctx.sessions.isActive(AGENT)).toBe(true); // reads as one long task
  });
});

// ---------------------------------------------------------------------------
// CireSnave's ruling: "They should be able to have queue_empty rederived from
// the queue itself, but they should not be able to set it to an invalid
// setting — queue_empty = true while the queue is not empty is an error."
//
// WHICH QUEUE. FAM observes exactly one: undelivered messages. It cannot see an
// agent's internal task list, which is why the field was declared rather than
// computed in the first place. That asymmetry decides the whole design:
//
//   FAM CAN DISPROVE "empty"  — messages are waiting, so work is pending.
//   FAM CANNOT PROVE "empty"  — an empty inbox says nothing about internal work.
//
// So rederivation is a CORRECTION, not a recompute. It overwrites a value the
// evidence contradicts and leaves alone one it merely cannot confirm. A
// rederivation that asserted `true` on an empty inbox would be FAM inventing a
// declaration on the entity's behalf — the exact thing the nullable default
// exists to prevent.
//
// And the error must be an ERROR. Silently writing `false` over a bad `true`
// is indistinguishable from success to the caller, who then believes a
// declaration that was never accepted.
// ---------------------------------------------------------------------------

describe('a declaration the queue contradicts is refused', () => {
  const BUSY = `busy@${ACCOUNT}`;
  const SENDER = `sender@${ACCOUNT}`;

  beforeAll(async () => {
    for (const id of [BUSY, SENDER]) {
      ctx.db
        .prepare(
          `INSERT OR IGNORE INTO entities (id, account_id, type, public_key, capabilities)
           VALUES (?, ?, 'agent', 'pk', '{"can_send":true}')`
        )
        .run(id, ACCOUNT);
    }
    await ctx.messages.sendDirectMessage(SENDER, BUSY, 'work for you');
  });

  test('declaring EMPTY with messages waiting is an error', () => {
    expect(ctx.messages.getUndeliveredCount(BUSY)).toBeGreaterThan(0);
    expect(() => ctx.entities.updateQueueEmpty(BUSY, true)).toThrow();
  });

  test('the refusal does not quietly write something else', () => {
    const before = ctx.entities.getById(BUSY)!.queue_empty;
    try { ctx.entities.updateQueueEmpty(BUSY, true); } catch { /* expected */ }
    expect(ctx.entities.getById(BUSY)!.queue_empty).toBe(before);
  });

  // Declaring BUSY is never contradicted: FAM cannot see internal work, so an
  // agent with an empty inbox may still legitimately have plenty to do.
  test('declaring NOT-empty is always allowed', () => {
    expect(() => ctx.entities.updateQueueEmpty(QUIET, false)).not.toThrow();
    expect(ctx.entities.getById(QUIET)!.queue_empty).toBe(false);
  });

  test('declaring empty is allowed once the queue drains', async () => {
    const pending = await ctx.messages.getUndelivered(BUSY);
    ctx.messages.markDelivered(BUSY, pending.map(m => m.id));
    expect(ctx.messages.getUndeliveredCount(BUSY)).toBe(0);
    expect(() => ctx.entities.updateQueueEmpty(BUSY, true)).not.toThrow();
  });
});

describe('rederivation corrects what the evidence contradicts', () => {
  const STALE = `stale@${ACCOUNT}`;
  const SENDER2 = `sender2@${ACCOUNT}`;

  beforeAll(() => {
    for (const id of [STALE, SENDER2]) {
      ctx.db
        .prepare(
          `INSERT OR IGNORE INTO entities (id, account_id, type, public_key, capabilities)
           VALUES (?, ?, 'agent', 'pk', '{"can_send":true}')`
        )
        .run(id, ACCOUNT);
    }
  });

  test('with messages waiting it sets NOT-empty', async () => {
    ctx.entities.updateQueueEmpty(STALE, true); // legitimate when declared
    await ctx.messages.sendDirectMessage(SENDER2, STALE, 'arrived after');

    const result = ctx.entities.rederiveQueueEmpty(STALE);

    expect(result.queue_empty).toBe(false);
    expect(result.corrected).toBe(true);
    expect(ctx.entities.getById(STALE)!.queue_empty).toBe(false);
  });

  // FAM cannot prove an empty queue, so it must not assert one. Leaving the
  // entity's own declaration standing is the honest outcome.
  test('with an empty queue it leaves the declaration ALONE', async () => {
    const pending = await ctx.messages.getUndelivered(STALE);
    ctx.messages.markDelivered(STALE, pending.map(m => m.id));
    ctx.entities.updateQueueEmpty(STALE, true);

    const result = ctx.entities.rederiveQueueEmpty(STALE);

    expect(result.corrected).toBe(false);
    expect(ctx.entities.getById(STALE)!.queue_empty).toBe(true);
  });

  test('it reports what it observed, so the caller learns something', () => {
    const result = ctx.entities.rederiveQueueEmpty(STALE);
    expect(typeof result.undelivered).toBe('number');
  });
});
