import { test, expect, describe, beforeAll } from 'bun:test';
import { getDatabaseContext } from '../index';
import type { DatabaseContext } from '../transaction';

// ============================================================================
// A free-text summary of what an entity is currently doing, with a stamp
// saying when it last said so.
//
// WHY IT EXISTS: of 17 peers observed on the predecessor system, the 5 carrying
// summaries were the only ones routable without broadcasting to everybody. Name
// and capabilities describe identity; routing needs current INTENT, and nothing
// else in the schema carries it.
//
// WHY THE STAMP EXISTS: a four-day-old summary read as current caused one
// project to conclude another was blocked on work that had already shipped, and
// act on it. The stamp moves the discount from something a reader must remember
// to something they cannot avoid seeing.
//
// THE TRAP, and ROADMAP walked into it. Its own note proposed reusing
// `last_seen` — "already recorded, so rendering 'set 4d ago' is nearly free".
// `last_seen` is CONNECTION-DERIVED. A live agent carrying a six-month-old
// summary would render "set 2 minutes ago", which is precisely the misreading
// the item exists to prevent, implemented by the fix. The stamp must record
// when the summary was ASSERTED.
//
// AND IT DIFFERS FROM last_state_change ON PURPOSE. That column records a
// CHANGE, so re-stating the same value must not move it. This one records the
// last time someone VOUCHED for the text, so re-asserting the same summary MUST
// refresh it: "still true" is new information about an old sentence.
// ============================================================================

const ACCOUNT = 'summary@example.com';
const AGENT = `worker@${ACCOUNT}`;
const SILENT = `silent@${ACCOUNT}`;

let ctx: DatabaseContext;

function read(id: string) {
  return ctx.db
    .prepare('SELECT summary, summary_set_at, last_seen FROM entities WHERE id = ?')
    .get(id) as { summary: string | null; summary_set_at: string | null; last_seen: string | null };
}

beforeAll(() => {
  ctx = getDatabaseContext();
  ctx.db.prepare('INSERT OR IGNORE INTO accounts (id) VALUES (?)').run(ACCOUNT);
  for (const id of [AGENT, SILENT]) {
    ctx.db
      .prepare(
        `INSERT OR IGNORE INTO entities (id, account_id, type, public_key, capabilities)
         VALUES (?, ?, 'agent', 'pk', '{"can_send":true}')`
      )
      .run(id, ACCOUNT);
  }
});

describe('a summary is set by the entity and stamped when asserted', () => {
  test('an entity that has never spoken has no summary and no stamp', () => {
    const row = read(SILENT);
    expect(row.summary).toBeNull();
    expect(row.summary_set_at).toBeNull();
  });

  test('setting one records the text and the moment', () => {
    ctx.entities.updateSummary(AGENT, 'Rebuilding the ingest pipeline; blocked on nothing.');
    const row = read(AGENT);
    expect(row.summary).toContain('ingest pipeline');
    expect(row.summary_set_at).not.toBeNull();
  });

  test('clearing it removes the text and the stamp together', () => {
    ctx.entities.updateSummary(AGENT, 'temporary');
    ctx.entities.updateSummary(AGENT, null);
    const row = read(AGENT);
    expect(row.summary).toBeNull();
    // A stamp without a summary would render an age for nothing.
    expect(row.summary_set_at).toBeNull();
  });
});

describe('the stamp records assertion, not liveness', () => {
  // THE DISCRIMINATOR. If this fails, the stamp is last_seen wearing a
  // different name and a live agent's stale summary reads as fresh — the exact
  // misreading the field exists to prevent.
  test('a HEARTBEAT does not refresh it', () => {
    ctx.entities.updateSummary(AGENT, 'steady work');
    ctx.db
      .prepare("UPDATE entities SET summary_set_at = datetime('now','-4 days') WHERE id = ?")
      .run(AGENT);
    const aged = read(AGENT).summary_set_at;

    const session = ctx.sessions.create(AGENT);
    ctx.sessions.updateHeartbeat(session.id);
    ctx.entities.updateStatus(AGENT, 'online'); // also touches last_seen

    expect(read(AGENT).summary_set_at).toBe(aged!);
  });

  test('going online moves last_seen but NOT the summary stamp', () => {
    const before = read(AGENT);
    ctx.entities.updateStatus(AGENT, 'online');
    const after = read(AGENT);

    expect(after.summary_set_at).toBe(before.summary_set_at!);
    expect(after.last_seen).not.toBeNull();
  });

  // Deliberately OPPOSITE to last_state_change, which ignores a repeat.
  // Staleness asks when someone last vouched for the text; re-asserting it is
  // vouching, and "still true" is new information about an old sentence.
  test('re-asserting the SAME summary DOES refresh the stamp', async () => {
    const text = 'unchanged but still accurate';
    ctx.entities.updateSummary(AGENT, text);
    ctx.db
      .prepare("UPDATE entities SET summary_set_at = datetime('now','-4 days') WHERE id = ?")
      .run(AGENT);
    const aged = read(AGENT).summary_set_at;

    ctx.entities.updateSummary(AGENT, text); // same words, said again

    expect(read(AGENT).summary_set_at).not.toBe(aged!);
  });
});

describe('the summary is bounded', () => {
  test('an overlong summary is refused rather than silently truncated', () => {
    // Truncation would publish a sentence the entity did not write, and the
    // point of the field is that it is the entity's own words.
    expect(() => ctx.entities.updateSummary(AGENT, 'x'.repeat(5000))).toThrow();
  });

  test('whitespace-only is treated as clearing, not as a summary', () => {
    ctx.entities.updateSummary(AGENT, 'real text');
    ctx.entities.updateSummary(AGENT, '   ');
    expect(read(AGENT).summary).toBeNull();
  });
});
