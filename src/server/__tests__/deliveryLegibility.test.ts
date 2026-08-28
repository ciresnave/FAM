import { test, expect, describe, beforeAll } from 'bun:test';
import { getDatabaseContext } from '../../db';
import { WebSocketManager } from '../websocket';
import { MessageSendService } from '../services/messageSend';
import { PermissionChecker } from '../services/permissionChecker';
import type { DatabaseContext } from '../../db/transaction';

// ============================================================================
// ANY OUTCOME THAT IS NOT DELIVERY MUST BE LEGIBLE TO THE SENDER.
//
// Sending returned `201 + message_id` whether the recipient was connected,
// deliberately paused, or offline for a week. The server computed the
// difference — pushToEntity has all three branches — and then threw it away.
//
// THE MEASURED HARM, from four days of running the predecessor system: of 12
// peers pinged in one window, 4 replied. The other 8 could not be told apart,
// and the sender read all 8 as "busy". They are three different situations:
//
//   pushed   -- frame written to a live socket: they have it, silence is theirs
//   paused   -- declared unavailable: queued deliberately, do not wait
//   offline  -- no connection: queued, they see it on reconnect
//
// Collapsing `paused` and `offline` into `pushed` turns "never received it"
// into "chose not to answer", which is the reading that makes a coordinator
// treat a dead lane as a thinking one.
//
// The outcome is captured AT THE MOMENT OF THE PUSH, not re-derived afterwards:
// re-querying connection state after the fact races with a disconnect and can
// report a delivery that did not happen.
//
// CAVEAT, deliberately preserved in the field name: availability is
// HONEST-BROADCAST, not enforced truth. `paused` reports what the recipient
// declared, not a guarantee about what it will do.
// ============================================================================

const ACCOUNT = 'legible@example.com';
const SENDER = `sender@${ACCOUNT}`;
const LIVE = `live@${ACCOUNT}`;
const PAUSED = `paused@${ACCOUNT}`;
const GONE = `gone@${ACCOUNT}`;

let ctx: DatabaseContext;
let wsManager: WebSocketManager;
let sendService: MessageSendService;

/** A socket that records what was written to it. */
function fakeSocket() {
  const frames: string[] = [];
  return {
    frames,
    send(data: string) { frames.push(data); },
    close() {},
    readyState: 1,
  };
}

function connect(entityId: string) {
  const session = ctx.sessions.create(entityId);
  const ws = fakeSocket();
  wsManager.handleConnection(ws, entityId, session.id);
  return ws;
}

beforeAll(() => {
  ctx = getDatabaseContext();
  wsManager = new WebSocketManager(ctx);
  sendService = new MessageSendService(ctx, wsManager, new PermissionChecker(ctx));
  wsManager.setSendService(sendService);

  ctx.db.prepare('INSERT OR IGNORE INTO accounts (id) VALUES (?)').run(ACCOUNT);
  for (const id of [SENDER, LIVE, PAUSED, GONE]) {
    ctx.db
      .prepare(
        `INSERT OR IGNORE INTO entities (id, account_id, type, public_key, capabilities)
         VALUES (?, ?, 'agent', 'pk', '{"can_send":true}')`
      )
      .run(id, ACCOUNT);
  }

  connect(LIVE);
  connect(PAUSED);
  ctx.entities.updateAvailability(PAUSED, 'unavailable');
  // GONE is deliberately never connected.
});

describe('the sender is told what happened to the message', () => {
  test('a connected, available recipient reports PUSHED', async () => {
    const result = await sendService.sendDirectMessage(SENDER, LIVE, 'are you there');
    expect(result.delivery.outcome).toBe('pushed');
  });

  test('a recipient who declared unavailable reports PAUSED, not delivered', async () => {
    const result = await sendService.sendDirectMessage(SENDER, PAUSED, 'later then');
    expect(result.delivery.outcome).toBe('paused');
  });

  test('an offline recipient reports OFFLINE, not delivered', async () => {
    const result = await sendService.sendDirectMessage(SENDER, GONE, 'anyone home');
    expect(result.delivery.outcome).toBe('offline');
  });

  // THE POINT. Three sends that previously produced identical responses must
  // now produce three distinguishable ones. Asserted as a set, because the
  // failure being prevented is exactly that two of them collapse.
  test('the three outcomes are mutually distinguishable', async () => {
    const outcomes = await Promise.all(
      [LIVE, PAUSED, GONE].map(async to =>
        (await sendService.sendDirectMessage(SENDER, to, 'ping')).delivery.outcome
      )
    );
    expect(new Set(outcomes).size).toBe(3);
  });
});

describe('the response carries the recipient state the decision rests on', () => {
  test('status and availability are reported', async () => {
    const { delivery } = await sendService.sendDirectMessage(SENDER, PAUSED, 'context');
    expect(delivery.recipient.availability).toBe('unavailable');
    expect(typeof delivery.recipient.status).toBe('string');
  });

  // Declared state travels with it: a recipient that has said it has work
  // pending is a different silence from one that has said nothing.
  test('declared queue state travels with the outcome', async () => {
    ctx.entities.updateQueueEmpty(GONE, false);
    const { delivery } = await sendService.sendDirectMessage(SENDER, GONE, 'busy?');
    expect(delivery.recipient.queue_empty).toBe(false);
  });

  test('never-declared queue state stays null rather than becoming a claim', async () => {
    const { delivery } = await sendService.sendDirectMessage(SENDER, LIVE, 'unknown queue');
    expect(delivery.recipient.queue_empty).toBeNull();
  });
});

describe('the outcome is observed, not inferred', () => {
  // If the outcome were re-derived from connection state after the push, a
  // disconnect in between would produce a report of a delivery that did not
  // happen. Recording it at the push is what makes it a fact rather than a
  // guess, so this asserts the reported outcome matches what the socket saw.
  test('PUSHED means a frame actually reached the socket', async () => {
    // Entity first: a session references it, so connecting before it exists
    // fails the foreign key and the socket never registers.
    ctx.db
      .prepare(
        `INSERT OR IGNORE INTO entities (id, account_id, type, public_key, capabilities)
         VALUES (?, ?, 'agent', 'pk', '{"can_send":true}')`
      )
      .run(`witness@${ACCOUNT}`, ACCOUNT);
    const ws = connect(`witness@${ACCOUNT}`);

    const before = ws.frames.length;
    const { delivery } = await sendService.sendDirectMessage(
      SENDER, `witness@${ACCOUNT}`, 'did this land'
    );

    if (delivery.outcome === 'pushed') {
      expect(ws.frames.length).toBeGreaterThan(before);
    } else {
      expect(ws.frames.length).toBe(before);
    }
  });
});
