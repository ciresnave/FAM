import { test, expect, describe, beforeAll, afterAll } from 'bun:test';
import { startServer, stopServer } from '../http';
import { getDatabaseContext } from '../../db';
import { hashToken } from '../../auth/oauth';
import { generateKeyPair, bufferToBase64 } from '../../crypto/keys';

// ============================================================================
// ⚠️ WRITTEN BECAUSE A MUTATION PROVED THESE RULES WERE UNGUARDED.
//
// `/channels/kick` refuses a requester who is not an admin or owner:
//
//     if (!requesterRole || requesterRole === 'member') { throw Forbidden }
//
// ONE CONDITION COVERING TWO CASES — a non-member, and a member without rank.
// The existing suite covered the first (an outsider gets 403) and not the
// second. Measured: deleting `|| requesterRole === 'member'`, so that ANY
// MEMBER CAN KICK ANY OTHER MEMBER, left all 68 tests passing.
//
// That is the masked-guard shape this codebase keeps finding: two checks
// sharing a line, one exercised, and the outcome identical for the case that
// IS tested. The privilege escalation is invisible from the green.
//
// ⚠️ THIS IS NOT "fine-grained permissions". The open question in DESIGN.md asks
// whether channels need a finer role model; measured, roles gate exactly three
// routes — invite, kick, set-role — all membership administration, and NOT
// messaging. Nothing in the tree expresses a want for a finer distinction. So
// the useful work was not adding an axis; it was guarding the one that exists.
// ============================================================================

const TEST_HOST = '127.0.0.1';
const TEST_SECRET = process.env.FAM_SERVER_SECRET!;
const ACCOUNT = 'chanauth@example.com';

let serverHandle: ReturnType<typeof startServer>;
let BASE: string;

/**
 * The endpoints this file touches, as a closed set.
 *
 * ⚠️ THIS DOES NOT CLEAR CODACY'S `node-ssrf` FINDING ON THE `fetch` BELOW, and
 * recording that is the point — I was about to make this change believing it
 * would. Measured against Codacy's API: the rule has 14 instances repo-wide and
 * SEVEN are sibling test helpers, including two that ALREADY use this exact
 * union (`encryptionKeyRoute.test.ts:77`, `entityKeyCustody.test.ts:65`). The
 * check is syntactic and the type is invisible to it.
 *
 * It earns its place anyway, for the reason `encryptionKeyRoute.test.ts` gives —
 * a typo'd path becomes a compile error rather than an expectation failure three
 * assertions later — and because it makes this PR's disposition CHECKABLE: "the
 * path cannot be attacker-controlled" stops being something I read off the call
 * sites once and becomes something the compiler enforces.
 */
type Endpoint = '/channels/kick' | '/channels/set-role';

async function api(path: Endpoint, body: unknown): Promise<{ status: number; data: any }> {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, data: await res.json().catch(() => null) };
}

function sessionFor(entityId: string): string {
  return getDatabaseContext().sessions.create(entityId).id;
}

/** Every request needs the caller's own session; role is read from the store. */
async function as(entityId: string, path: Endpoint, body: Record<string, unknown>) {
  return api(path, { entity_id: entityId, session_id: sessionFor(entityId), ...body });
}

const OWNER = `owner@${ACCOUNT}`;
const ADMIN_A = `admina@${ACCOUNT}`;
const ADMIN_B = `adminb@${ACCOUNT}`;
const MEMBER_A = `membera@${ACCOUNT}`;
const MEMBER_B = `memberb@${ACCOUNT}`;

let channelId: string;

beforeAll(async () => {
  const ctx = getDatabaseContext();
  ctx.db.prepare('INSERT OR IGNORE INTO accounts (id) VALUES (?)').run(ACCOUNT);
  ctx.db
    .prepare(
      `INSERT OR IGNORE INTO authorizations (id, account_id, server_id, token_hash)
       VALUES (?, ?, 'local', ?)`
    )
    .run(`auth-${ACCOUNT}`, ACCOUNT, await hashToken(`token-${ACCOUNT}`, TEST_SECRET));

  for (const id of [OWNER, ADMIN_A, ADMIN_B, MEMBER_A, MEMBER_B]) {
    const keys = await generateKeyPair();
    ctx.db
      .prepare(
        `INSERT OR IGNORE INTO entities (id, account_id, type, public_key, capabilities)
         VALUES (?, ?, 'agent', ?, '{"can_send":true,"can_create_channels":true,"can_join_channel":true}')`
      )
      .run(id, ACCOUNT, bufferToBase64(keys.publicKey));
  }

  const channel = ctx.channels.create('auth-room', OWNER, true);
  channelId = channel.id;
  ctx.channels.addMember(channelId, ADMIN_A, 'admin');
  ctx.channels.addMember(channelId, ADMIN_B, 'admin');
  ctx.channels.addMember(channelId, MEMBER_A, 'member');
  ctx.channels.addMember(channelId, MEMBER_B, 'member');

  // Ephemeral port, for the reason `integration.test.ts` documents: a fixed port
  // collides with the PREVIOUS run's client sockets in TIME_WAIT, the bind
  // throws inside `beforeAll`, and the whole file's tests vanish from the count.
  serverHandle = startServer({ port: 0, host: TEST_HOST });
  BASE = `http://${TEST_HOST}:${serverHandle.port}`;
});

afterAll(() => stopServer(serverHandle));

describe('⚠️ kick — the requester needs rank, not merely membership', () => {
  test('a plain MEMBER cannot kick another member', async () => {
    // THE UNGUARDED RULE. The suite tested a NON-member being refused; a member
    // without rank is a different case sharing the same `if`, and deleting it
    // left every test green.
    const { status } = await as(MEMBER_A, '/channels/kick', {
      channel_id: channelId,
      target_entity: MEMBER_B,
    });

    expect(status).toBe(403);
    // And the target is still there — a refusal that had already acted would
    // satisfy the status assertion.
    expect(getDatabaseContext().channels.isMember(channelId, MEMBER_B)).toBe(true);
  });

  test('control: an ADMIN can kick a member, so the refusal above is about RANK', async () => {
    // Without this, the test above passes against a route that refuses
    // everyone, which would be a different defect wearing the same green.
    const { status } = await as(ADMIN_A, '/channels/kick', {
      channel_id: channelId,
      target_entity: MEMBER_B,
    });

    expect(status).toBe(200);
    expect(getDatabaseContext().channels.isMember(channelId, MEMBER_B)).toBe(false);
  });
});

describe('⚠️ kick — rank does not permit kicking an equal or a superior', () => {
  test('an admin cannot kick another ADMIN', async () => {
    const { status } = await as(ADMIN_A, '/channels/kick', {
      channel_id: channelId,
      target_entity: ADMIN_B,
    });

    expect(status).toBe(403);
    expect(getDatabaseContext().channels.isMember(channelId, ADMIN_B)).toBe(true);
  });

  test('an admin cannot kick the OWNER', async () => {
    // The one that turns a channel takeover into a refusal.
    const { status } = await as(ADMIN_A, '/channels/kick', {
      channel_id: channelId,
      target_entity: OWNER,
    });

    expect(status).toBe(403);
    expect(getDatabaseContext().channels.isMember(channelId, OWNER)).toBe(true);
  });
});

describe('⚠️ set-role — ownership cannot be granted through it', () => {
  test('even the owner cannot promote someone to OWNER', async () => {
    // `role` is restricted to admin|member. Ownership transfer is not this
    // route's job, and a route that quietly allowed it would make a channel
    // have two owners — a state nothing else in the model expects.
    const { status } = await as(OWNER, '/channels/set-role', {
      channel_id: channelId,
      target_entity: MEMBER_A,
      role: 'owner',
    });

    expect(status).toBe(400);
    expect(getDatabaseContext().channels.getMemberRole(channelId, MEMBER_A)).toBe('member');
  });

  test('control: the owner CAN promote to admin, so the refusal is about the ROLE', async () => {
    const { status } = await as(OWNER, '/channels/set-role', {
      channel_id: channelId,
      target_entity: MEMBER_A,
      role: 'admin',
    });

    expect(status).toBe(200);
    expect(getDatabaseContext().channels.getMemberRole(channelId, MEMBER_A)).toBe('admin');
  });
});
