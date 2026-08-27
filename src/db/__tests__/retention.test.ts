import { test, expect, describe, beforeAll } from 'bun:test';
import { getDatabaseContext } from '../index';
import type { DatabaseContext } from '../transaction';

// ============================================================================
// Retention must not depend on the SHAPE of the stored timestamp.
//
// deleteOlderThan compared `sent_at` against datetime('now', '-N days'), which
// yields "YYYY-MM-DD HH:MM:SS" — a SPACE separator and no Z. FAM writes the
// same shape, so a plain string comparison happened to be correct.
//
// It stops being correct the moment a row carries ISO-8601 (a federation
// import, a client-supplied timestamp, a restored backup): 'T' (0x54) sorts
// above ' ' (0x20), so a row on the CUTOFF DAY is retained however old it is.
// Only that day is affected, which is why it survives casual testing — the same
// defect already found and fixed in the claude-peers broker.
// ============================================================================

const ACCOUNT = 'ret@example.com';
const A = `a@${ACCOUNT}`;
const B = `b@${ACCOUNT}`;

let ctx: DatabaseContext;

beforeAll(() => {
  ctx = getDatabaseContext();
  ctx.db.prepare('INSERT OR IGNORE INTO accounts (id) VALUES (?)').run(ACCOUNT);
  for (const id of [A, B]) {
    ctx.db
      .prepare(
        `INSERT OR IGNORE INTO entities (id, account_id, type, public_key, capabilities)
         VALUES (?, ?, 'agent', 'pk', '{"can_send":true}')`
      )
      .run(id, ACCOUNT);
  }
});

function insertAt(text: string, sentAt: string): void {
  ctx.db
    .prepare(
      `INSERT INTO messages (from_entity, to_entity, text, sent_at) VALUES (?, ?, ?, ?)`
    )
    .run(A, B, text, sentAt);
}

function present(text: string): boolean {
  const row = ctx.db.prepare('SELECT 1 FROM messages WHERE text = ?').get(text);
  return row !== null && row !== undefined;
}

describe('retention sweeps by instant, not by string shape', () => {
  test('an ISO-8601 row on the cutoff day is swept like a native-shape one', () => {
    // Both rows are the SAME instant, an hour older than the cutoff. Only the
    // spelling differs. Any difference in outcome is the bug.
    const cutoff = (
      ctx.db.prepare("SELECT datetime('now','-30 days') d").get() as { d: string }
    ).d;
    const [day, time] = cutoff.split(' ');
    const hour = String(Math.max(0, parseInt(time!.slice(0, 2), 10) - 1)).padStart(2, '0');
    const older = `${hour}${time!.slice(2)}`;

    insertAt('ret-native-cutoff-day', `${day} ${older}`);
    insertAt('ret-iso-cutoff-day', `${day}T${older}.000Z`);

    ctx.messages.deleteOlderThan(30);

    expect(present('ret-native-cutoff-day')).toBe(false);
    expect(present('ret-iso-cutoff-day')).toBe(false);
  });

  test('rows newer than the window survive, whichever shape they carry', () => {
    const recent = (
      ctx.db.prepare("SELECT datetime('now','-1 days') d").get() as { d: string }
    ).d;
    const [day, time] = recent.split(' ');

    insertAt('ret-native-recent', recent);
    insertAt('ret-iso-recent', `${day}T${time}.000Z`);

    ctx.messages.deleteOlderThan(30);

    expect(present('ret-native-recent')).toBe(true);
    expect(present('ret-iso-recent')).toBe(true);
  });
});

// ============================================================================
// Retention must not destroy mail that was never delivered.
//
// The sweep bounded deletion by AGE alone. A message nobody ever collected is
// exactly as old as one that was read the moment it arrived, so an undelivered
// message aged out silently: the sender was told 201, the recipient never saw
// it, and nothing recorded that it had been dropped. This is the same defect
// already fixed in the claude-peers broker after it destroyed queued mail on
// eviction — the broker's sweep filters `delivered = 1`; this one did not.
//
// Found by asking a question ABOUT the sweep, not by testing it. The retention
// test above is scrupulous about timestamp SHAPE and passes perfectly while the
// destruction happens, because shape was the only dimension it examined.
//
// The second test is the discriminator and is not optional: without it, a
// deleteOlderThan that deletes NOTHING satisfies the first test completely.
// ============================================================================

describe('retention spares mail that was never delivered', () => {
  async function sendAndAge(text: string, days: number): Promise<number> {
    const m = await ctx.messages.sendDirectMessage(A, B, text);
    ctx.db
      .prepare(`UPDATE messages SET sent_at = datetime('now', '-' || ? || ' days') WHERE id = ?`)
      .run(days, m.id);
    return m.id;
  }

  test('an UNDELIVERED message survives however old it is', async () => {
    await sendAndAge('ret-undelivered-ancient', 400);

    ctx.messages.deleteOlderThan(30);

    expect(present('ret-undelivered-ancient')).toBe(true);
  });

  // THE DISCRIMINATOR. Retention must still do its job, or the fix above is
  // indistinguishable from disabling the sweep entirely.
  test('a DELIVERED message of the same age is still swept', async () => {
    const id = await sendAndAge('ret-delivered-ancient', 400);
    ctx.messages.markDelivered(B, [id]);

    ctx.messages.deleteOlderThan(30);

    expect(present('ret-delivered-ancient')).toBe(false);
  });
});
