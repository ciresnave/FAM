import { test, expect, describe, beforeAll, afterAll } from 'bun:test';
import { startServer, stopServer } from '../http';
import { getDatabaseContext } from '../../db';

// ============================================================================
// ⚠️ AN INVITATION BELONGS TO THE ENTITY IT NAMES, AND NOTHING TESTED THAT.
//
//     src/server/routes/channels.ts — POST /channels/decline-invite
//     if (invitation.invited_entity !== entity_id) {
//       throw new ForbiddenError('This invitation is not for you');
//     }
//
// Found by coverage: this refusal has ZERO hits across the whole suite, so no
// test distinguishes the guard from its absence. Confirmed by deleting it —
// 793 pass, 0 fail. See `channelMembershipBoundaries.test.ts` for why a
// zero-hit deny body is a stronger result than a surviving mutant.
//
// ⚠️ THE HARM IS NOT ESCALATION, WHICH IS WHY IT IS EASY TO SKIP. Nobody gains
// access by declining an invitation. What they gain is the ability to DESTROY
// someone else's — silently, with a 200, leaving the invitee waiting for a
// channel they were told to expect. An authorisation guard whose failure looks
// like nothing happening is the one least likely to be reported by a user and
// least likely to be written by a test author looking for privilege escalation.
//
// The `!invitation` half at :417 is exercised here too, for the same reason the
// channel work split its compound guards into separate tests: two cases sharing
// one code path is how the second goes unmeasured.
// ============================================================================

const TEST_HOST = '127.0.0.1';
const ACCOUNT = 'inviteown@example.com';

const OWNER = `owner@${ACCOUNT}`;
const INVITEE = `invitee@${ACCOUNT}`;
const MEDDLER = `meddler@${ACCOUNT}`;
// ⚠️ THE CONTROL GETS ITS OWN INVITEE AND ITS OWN INVITATION, so it does not
// depend on the test above having REFUSED. Sharing them, mutating the ownership
// guard let MEDDLER destroy the invitation and the control failed too — a
// cascade that reads as a second detection and is not one.
const INVITEE_2 = `invitee2@${ACCOUNT}`;

let serverHandle: ReturnType<typeof startServer>;
let BASE: string;
let channelId: string;

async function decline(
  entityId: string,
  invitationId: string
): Promise<{ status: number; data: any }> {
  const session = getDatabaseContext().sessions.create(entityId).id;
  const res = await fetch(`${BASE}/channels/decline-invite`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      entity_id: entityId,
      session_id: session,
      invitation_id: invitationId,
    }),
  });
  return { status: res.status, data: await res.json().catch(() => null) };
}

function pendingFor(entityId: string): number {
  return getDatabaseContext()
    .invitations.getPendingForEntity(entityId)
    .filter((i) => i.channel_id === channelId).length;
}

beforeAll(async () => {
  const ctx = getDatabaseContext();
  ctx.db.prepare('INSERT OR IGNORE INTO accounts (id) VALUES (?)').run(ACCOUNT);

  const entity = ctx.db.prepare(
    `INSERT OR IGNORE INTO entities (id, account_id, type, public_key, capabilities)
     VALUES (?, ?, 'agent', 'pk', '{"can_send":true,"can_create_channels":true,"can_join_channel":true}')`
  );
  for (const id of [OWNER, INVITEE, MEDDLER, INVITEE_2]) entity.run(id, ACCOUNT);

  channelId = ctx.channels.create('invite-room', OWNER, false).id;

  // Ephemeral port, for the reason `integration.test.ts` documents.
  serverHandle = startServer({ port: 0, host: TEST_HOST });
  BASE = `http://${TEST_HOST}:${serverHandle.port}`;
});

afterAll(() => stopServer(serverHandle));

describe("⚠️ decline-invite — you may only decline your OWN invitation", () => {
  test("another entity cannot decline an invitation addressed to someone else", async () => {
    const ctx = getDatabaseContext();
    const invitation = ctx.invitations.create(channelId, OWNER, INVITEE);

    const { status } = await decline(MEDDLER, invitation.id);

    expect(status).toBe(403);
    // ⚠️ THE ROW IS THE POINT. A refusal that had already declined it would
    // satisfy the status assertion and still have destroyed the invitation —
    // which is the entire harm, since nobody is trying to GAIN anything here.
    expect(pendingFor(INVITEE)).toBe(1);
  });

  test('an invitation id that names nothing is a 404, not a 403', async () => {
    // The other half of the pair, and the distinction is load-bearing: 403 says
    // "it exists and is not yours", 404 says "there is no such invitation".
    // Collapsing them would turn this route into an oracle for whether an
    // invitation id is real.
    const { status } = await decline(MEDDLER, '00000000-0000-4000-8000-000000000000');
    expect(status).toBe(404);
  });

  test('control: the INVITEE can decline it, so the refusal is about ownership', async () => {
    // ⚠️ Without this, the first test passes against a route that refuses every
    // decline — a different defect wearing the same green, and one that would
    // leave every invitee unable to say no.
    const ctx = getDatabaseContext();
    const own = ctx.invitations.create(channelId, OWNER, INVITEE_2);

    const { status } = await decline(INVITEE_2, own.id);

    expect(status).toBe(200);
    expect(pendingFor(INVITEE_2)).toBe(0);
  });
});
