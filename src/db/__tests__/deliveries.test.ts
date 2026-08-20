import { test, expect, describe, beforeAll } from 'bun:test';
import { getDatabaseContext } from '../index';
import type { DatabaseContext } from '../transaction';

// ============================================================================
// Per-recipient channel delivery
//
// `messages.delivered` is a SINGLE flag shared by every recipient of a channel
// message. When one member acknowledges, the message stops being undelivered
// for everyone — so a member who was offline, or paused via availability, never
// receives it. The flag answers "has anyone seen this?" while every caller
// reads it as "has THIS entity seen this?".
//
// Delivery is per (message, recipient), so it needs its own rows.
// ============================================================================

const ACCOUNT = 'deliv@example.com';
const A = `alice@${ACCOUNT}`;
const B = `bob@${ACCOUNT}`;
const C = `carol@${ACCOUNT}`;

let ctx: DatabaseContext;
let channelId: string;

function seedEntity(id: string) {
  ctx.db
    .prepare(
      `INSERT OR IGNORE INTO entities (id, account_id, type, public_key, capabilities)
       VALUES (?, ?, 'agent', 'pk', '{"can_send":true}')`
    )
    .run(id, ACCOUNT);
}

beforeAll(() => {
  ctx = getDatabaseContext();
  ctx.db.prepare(`INSERT OR IGNORE INTO accounts (id) VALUES (?)`).run(ACCOUNT);
  [A, B, C].forEach(seedEntity);

  const channel = ctx.channels.create('deliv-channel', A, false);
  channelId = channel.id;
  ctx.channels.addMember(channelId, B, 'member');
});

describe('per-recipient channel delivery', () => {
  // THE BUG: one member's acknowledgement currently hides the message from
  // every other member.
  test("one member's ack does not hide the message from another member", async () => {
    const msg = await ctx.messages.sendChannelMessage(A, channelId, 'to the channel');

    ctx.messages.markDelivered(B, [msg.id]);

    // C is not a member; B has acked. Add a third member BEFORE sending next
    // time — here we assert the sender's ack does not affect a real recipient.
    const bUndelivered = await ctx.messages.getUndelivered(B, 50);
    expect(bUndelivered.some((m) => m.id === msg.id)).toBe(false);

    // A second member must still be waiting for it.
    ctx.channels.addMember(channelId, C, 'member');
    const msg2 = await ctx.messages.sendChannelMessage(A, channelId, 'second message');

    ctx.messages.markDelivered(B, [msg2.id]);

    const cUndelivered = await ctx.messages.getUndelivered(C, 50);
    expect(cUndelivered.some((m) => m.id === msg2.id)).toBe(true);
  });

  test('the sender does not receive their own channel message', async () => {
    const msg = await ctx.messages.sendChannelMessage(A, channelId, 'from alice');
    const aUndelivered = await ctx.messages.getUndelivered(A, 50);
    expect(aUndelivered.some((m) => m.id === msg.id)).toBe(false);
  });

  // Fan-out happens at SEND time, so joining later does not hand you history
  // that was never addressed to you.
  test('a member who joins after a message was sent does not receive it', async () => {
    const late = `dave@${ACCOUNT}`;
    seedEntity(late);

    const msg = await ctx.messages.sendChannelMessage(A, channelId, 'before dave joined');
    ctx.channels.addMember(channelId, late, 'member');

    const undelivered = await ctx.messages.getUndelivered(late, 50);
    expect(undelivered.some((m) => m.id === msg.id)).toBe(false);
  });

  test('undelivered counts are per recipient', async () => {
    const before = ctx.messages.getUndeliveredCount(C);
    const msg = await ctx.messages.sendChannelMessage(A, channelId, 'count me');

    expect(ctx.messages.getUndeliveredCount(C)).toBe(before + 1);

    ctx.messages.markDelivered(C, [msg.id]);
    expect(ctx.messages.getUndeliveredCount(C)).toBe(before);

    // B is also a member and has NOT acked this one.
    const bUndelivered = await ctx.messages.getUndelivered(B, 50);
    expect(bUndelivered.some((m) => m.id === msg.id)).toBe(true);
  });

  test('direct messages are delivered to their recipient only', async () => {
    const msg = await ctx.messages.sendDirectMessage(A, B, 'private');

    const cUndelivered = await ctx.messages.getUndelivered(C, 50);
    expect(cUndelivered.some((m) => m.id === msg.id)).toBe(false);

    const bUndelivered = await ctx.messages.getUndelivered(B, 50);
    expect(bUndelivered.some((m) => m.id === msg.id)).toBe(true);

    ctx.messages.markDelivered(B, [msg.id]);
    const bAfter = await ctx.messages.getUndelivered(B, 50);
    expect(bAfter.some((m) => m.id === msg.id)).toBe(false);
  });

  test('acking a message addressed to somebody else does nothing', async () => {
    const msg = await ctx.messages.sendDirectMessage(A, B, 'not for carol');

    ctx.messages.markDelivered(C, [msg.id]);

    const bUndelivered = await ctx.messages.getUndelivered(B, 50);
    expect(bUndelivered.some((m) => m.id === msg.id)).toBe(true);
  });
});
