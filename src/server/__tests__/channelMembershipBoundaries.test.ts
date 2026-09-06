import { test, expect, describe, beforeAll, afterAll } from 'bun:test';
import { startServer, stopServer } from '../http';
import { getDatabaseContext } from '../../db';

// ============================================================================
// ⚠️ TWO DENY PATHS THAT NO TEST HAS EVER EXECUTED — FOUND BY COVERAGE, NOT BY
// MUTATION, AND THAT DIFFERENCE IS THE METHOD WORTH KEEPING.
//
// The previous sweep mutated the ten COMPOUND authorisation guards and stated
// plainly that the thirty SIMPLE ones were a different question it had not
// answered. This answers it, and the instrument had to change: a simple guard
// has no masked half to delete, so "which half is unexercised" is the wrong
// question. The right one is whether the REFUSAL EVER HAPPENS AT ALL.
//
// `bun test --coverage` answers that directly. Of 40 deny-guards, SIX have a
// body the suite never executes — the refusal is never taken by any test:
//
//     channels.ts:130  if (!channel.is_public)            <- here
//     channels.ts:132  if (!hasInvitation)                <- here
//     channels.ts:322  if (!inviterRole || ...)           (covered by the
//                                                          channel-authorization
//                                                          work, not yet merged)
//     channels.ts:417  if (!invitation)                   <- invitationOwnership
//     channels.ts:421  if (invitation.invited_entity ...) <- invitationOwnership
//     messages.ts:277  if (!isMember(channel_id, ...))    <- here
//
// ⚠️ A ZERO-HIT DENY BODY IS A STRONGER RESULT THAN A SURVIVING MUTANT, and it
// costs one run instead of one run per guard. If the refusal never executes,
// no test can distinguish the guard from its absence — the mutant is
// GUARANTEED to survive, and there is nothing left to measure. Confirmed
// anyway, because a deduction is not a measurement: all three of this file's
// and the sibling file's guards deleted together left 793 pass, 0 fail.
//
// ⚠️ AND COVERAGE IS THE INSTRUMENT THAT MISSES THE OTHER DIRECTION. A deny
// body that DOES execute proves only that some test reached it, never that any
// test ASSERTED on it. Coverage finds the never-reached; mutation finds the
// reached-but-unasserted. Neither substitutes for the other, and this project
// now has one instance of each.
//
// SUBJECT HERE: membership is what gates a private channel, on the way IN and
// on the way to its HISTORY. Both were unguarded by tests.
// ============================================================================

const TEST_HOST = '127.0.0.1';
const ACCOUNT = 'chanbounds@example.com';

const OWNER = `owner@${ACCOUNT}`;
const MEMBER = `member@${ACCOUNT}`;
const OUTSIDER = `outsider@${ACCOUNT}`;
const INVITED = `invited@${ACCOUNT}`;
// ⚠️ A SEPARATE NON-MEMBER FOR THE HISTORY TESTS, so they do not depend on the
// join tests above having REFUSED. With OUTSIDER shared, mutating the join
// guard let OUTSIDER in and the history test failed too — a cascade that reads
// as a second detection and is not one.
const STRANGER = `stranger@${ACCOUNT}`;

let serverHandle: ReturnType<typeof startServer>;
let BASE: string;
let privateChannel: string;

type Endpoint = '/channels/join' | '/messages/history';

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
  ctx.db.prepare('INSERT OR IGNORE INTO accounts (id) VALUES (?)').run(ACCOUNT);

  const entity = ctx.db.prepare(
    `INSERT OR IGNORE INTO entities (id, account_id, type, public_key, capabilities)
     VALUES (?, ?, 'agent', 'pk', '{"can_send":true,"can_create_channels":true,"can_join_channel":true}')`
  );
  for (const id of [OWNER, MEMBER, OUTSIDER, INVITED, STRANGER]) entity.run(id, ACCOUNT);

  // is_public = false. The whole subject.
  privateChannel = ctx.channels.create('the-private-room', OWNER, false).id;
  ctx.channels.addMember(privateChannel, MEMBER, 'member');

  // Ephemeral port, for the reason `integration.test.ts` documents.
  serverHandle = startServer({ port: 0, host: TEST_HOST });
  BASE = `http://${TEST_HOST}:${serverHandle.port}`;
});

afterAll(() => stopServer(serverHandle));

describe('⚠️ joining a PRIVATE channel needs an invitation', () => {
  test('an uninvited entity is REFUSED', async () => {
    const { status } = await as(OUTSIDER, '/channels/join', { channel_id: privateChannel });

    expect(status).toBe(403);
    // Membership, not just the status: a refusal that had already added the row
    // would satisfy a status assertion and leave the outsider inside.
    expect(getDatabaseContext().channels.isMember(privateChannel, OUTSIDER)).toBe(false);
  });

  test('control: an INVITED entity may join, so the refusal is about the invitation', async () => {
    // ⚠️ Without this, the test above passes against a route that refuses every
    // join of a private channel — including the invited case the feature exists
    // for. A different defect wearing the same green.
    const ctx = getDatabaseContext();
    ctx.invitations.create(privateChannel, OWNER, INVITED);

    const { status } = await as(INVITED, '/channels/join', { channel_id: privateChannel });

    expect(status).toBe(200);
    expect(ctx.channels.isMember(privateChannel, INVITED)).toBe(true);
  });

  test('control: a PUBLIC channel needs no invitation, so the refusal is about privacy', async () => {
    // The other half of `if (!channel.is_public)`. Without it, a route that
    // demanded an invitation for EVERY channel would pass both tests above.
    const ctx = getDatabaseContext();
    const open = ctx.channels.create('the-open-room', OWNER, true).id;

    const { status } = await as(OUTSIDER, '/channels/join', { channel_id: open });

    expect(status).toBe(200);
    expect(ctx.channels.isMember(open, OUTSIDER)).toBe(true);
  });
});

describe("⚠️ reading a channel's HISTORY needs membership", () => {
  test('a non-member is REFUSED', async () => {
    // The most consequential of the never-executed refusals: without it, any
    // entity could read any channel's entire history. Confidentiality, not
    // merely permission.
    const { status } = await as(STRANGER, '/messages/history', { channel_id: privateChannel });

    expect(status).toBe(403);
  });

  test('control: a MEMBER can read it, so the refusal is about membership', async () => {
    const { status, data } = await as(MEMBER, '/messages/history', { channel_id: privateChannel });

    expect(status).toBe(200);
    expect(Array.isArray(data.messages)).toBe(true);
  });
});
