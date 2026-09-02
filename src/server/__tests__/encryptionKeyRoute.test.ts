import { test, expect, describe, beforeAll, afterAll } from 'bun:test';
import { startServer, stopServer } from '../http';
import { getDatabaseContext } from '../../db';
import { hashToken } from '../../auth/oauth';

// ============================================================================
// Publishing an entity's X25519 public key, so others can seal messages to it.
//
// ⚠️ THE ROUTE PUBLISHES A PUBLIC KEY. IT NEVER ACCEPTS A PRIVATE ONE, AND THE
// SERVER NEVER GENERATES A PAIR. Both would put the private half where FAM
// could read the entity's mail, which is the exact property sealing exists to
// remove. The entity generates its own pair and tells the server the public
// half — that is the whole protocol.
//
// READING a key is deliberately NOT a new endpoint. `encryption_public_key`
// rides on the entity representation the caller is already entitled to see, so
// its visibility is whatever the directory already grants. A second endpoint
// would be a second answer to "may A see B", and the existing one is the tested
// one — the same reason this codebase has exactly one session-authentication
// implementation.
// ============================================================================

const TEST_PORT = 17913;
const TEST_HOST = '127.0.0.1';
const URL_BASE = `http://${TEST_HOST}:${TEST_PORT}`;
const TEST_SECRET = process.env.FAM_SERVER_SECRET!;

process.env.FAM_PORT = String(TEST_PORT);
process.env.FAM_HOST = TEST_HOST;

const ACCOUNT = 'keyroute@example.com';
const OTHER_ACCOUNT = 'stranger@example.com';
const ALICE = `alice@${ACCOUNT}`;
const BOB = `bob@${ACCOUNT}`;
const OUTSIDER = `outsider@${OTHER_ACCOUNT}`;

const X25519_KEY = Buffer.alloc(32, 9).toString('base64');
const OTHER_KEY = Buffer.alloc(32, 4).toString('base64');

let serverHandle: ReturnType<typeof startServer>;

async function seedAccount(accountId: string): Promise<void> {
  const ctx = getDatabaseContext();
  ctx.db.prepare('INSERT OR IGNORE INTO accounts (id) VALUES (?)').run(accountId);
  const tokenHash = await hashToken(`token-${accountId}`, TEST_SECRET);
  ctx.db
    .prepare(
      `INSERT OR IGNORE INTO authorizations (id, account_id, server_id, token_hash)
       VALUES (?, ?, 'local', ?)`
    )
    .run(`auth-${accountId}`, accountId, tokenHash);
}

function seedEntity(id: string, accountId: string): void {
  getDatabaseContext()
    .db.prepare(
      `INSERT OR IGNORE INTO entities (id, account_id, type, public_key, capabilities)
       VALUES (?, ?, 'agent', 'ed25519-identity-key', '{"can_send":true}')`
    )
    .run(id, accountId);
}

function sessionFor(entityId: string): string {
  return getDatabaseContext().sessions.create(entityId).id;
}

/**
 * The endpoints this file exercises, as a closed set.
 *
 * A `string` parameter here made a typo'd path an expectation failure three
 * assertions later; a union makes it a compile error. It also states what this
 * file touches without reading every call.
 */
type Endpoint = '/entities/encryption-key' | '/entities/list';

async function post(path: Endpoint, body: unknown): Promise<{ status: number; data: any }> {
  const res = await fetch(`${URL_BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, data: await res.json().catch(() => null) };
}

beforeAll(async () => {
  await seedAccount(ACCOUNT);
  await seedAccount(OTHER_ACCOUNT);
  seedEntity(ALICE, ACCOUNT);
  seedEntity(BOB, ACCOUNT);
  seedEntity(OUTSIDER, OTHER_ACCOUNT);
  serverHandle = startServer({ port: TEST_PORT, host: TEST_HOST });
});

afterAll(() => {
  stopServer(serverHandle);
});

describe('an entity publishes its own encryption key', () => {
  test('a session-authenticated entity can set it', async () => {
    const { status, data } = await post('/entities/encryption-key', {
      session_id: sessionFor(ALICE),
      encryption_public_key: X25519_KEY,
    });

    expect(status).toBe(200);
    expect(data.encryption_public_key).toBe(X25519_KEY);
    expect(getDatabaseContext().entities.getEncryptionKey(ALICE)).toBe(X25519_KEY);
  });

  test('an unauthenticated call is refused', async () => {
    const { status } = await post('/entities/encryption-key', {
      encryption_public_key: X25519_KEY,
    });
    expect(status).toBe(401);
  });

  test('naming another entity in the body is REFUSED, not quietly ignored', async () => {
    // ⚠️ The rule this codebase enforces everywhere: identity comes from the
    // session, never the body. A route that honoured `entity_id` here would let
    // any authenticated entity replace ANY other entity's encryption key — not
    // a disclosure bug but a full message-interception one, since every
    // subsequent sender would seal to the attacker's key.
    //
    // This test originally expected 200 with the field ignored. The actual
    // behaviour is stronger and `requireEntitySession` says why: "Disagreement
    // is rejected rather than ignored: silently overriding it would hide client
    // bugs, and a client that thinks it is acting as someone else should be
    // told." Corrected to assert the behaviour that exists, which is the one
    // worth having — an ignored field leaves the caller believing it succeeded
    // at something it never did.
    const aliceBefore = getDatabaseContext().entities.getEncryptionKey(ALICE);
    const bobBefore = getDatabaseContext().entities.getEncryptionKey(BOB);

    const { status } = await post('/entities/encryption-key', {
      session_id: sessionFor(ALICE),
      entity_id: BOB,
      encryption_public_key: OTHER_KEY,
    });

    expect(status).toBe(401);
    // NEITHER key moves. Rejecting the request but writing the caller's key
    // anyway would be the same defect wearing an error code.
    expect(getDatabaseContext().entities.getEncryptionKey(BOB)).toBe(bobBefore);
    expect(getDatabaseContext().entities.getEncryptionKey(ALICE)).toBe(aliceBefore);
  });

  test('a body entity_id that AGREES with the session is accepted', async () => {
    // The control. Without it the test above passes for a route that rejects
    // every request carrying an `entity_id` at all, or rejects everything.
    const { status, data } = await post('/entities/encryption-key', {
      session_id: sessionFor(ALICE),
      entity_id: ALICE,
      encryption_public_key: OTHER_KEY,
    });

    expect(status).toBe(200);
    expect(data.encryption_public_key).toBe(OTHER_KEY);
    expect(getDatabaseContext().entities.getEncryptionKey(ALICE)).toBe(OTHER_KEY);
  });

  test('a malformed key is refused with 400 and nothing is stored', async () => {
    const ctx = getDatabaseContext();
    ctx.entities.setEncryptionKey(BOB, X25519_KEY);

    const { status } = await post('/entities/encryption-key', {
      session_id: sessionFor(BOB),
      encryption_public_key: 'dG9vIHNob3J0',
    });

    expect(status).toBe(400);
    // The previous key survives. A rejected update that half-applied would
    // leave an entity unreachable by every future sender.
    expect(ctx.entities.getEncryptionKey(BOB)).toBe(X25519_KEY);
  });

  test('an empty string is refused as "you cannot clear it", not as a length error', async () => {
    // ⚠️ THIS TEST EXISTS BECAUSE THE CLAUSE IT COVERS SURVIVED A MUTATION.
    //
    // Deleting `|| encryption_public_key === ''` from the guard changed no
    // status code and stored nothing extra: '' falls through to
    // setEncryptionKey, which rejects it as not-32-bytes. Same 400, same
    // absence of a write. The whole suite stayed green.
    //
    // What changes is the MESSAGE, and the message is the feature. A client
    // sending '' is plausibly trying to CLEAR its key. "must be 32 bytes; got
    // 0" tells that client its key was the wrong length and invites a retry
    // with a different key. The real answer is that clearing is not an
    // operation, because it would silently downgrade every future message to
    // this entity.
    //
    // So the clause carries meaning the length check cannot, and asserting the
    // status alone would have left it unprotected.
    const ctx = getDatabaseContext();
    ctx.entities.setEncryptionKey(BOB, X25519_KEY);

    const { status, data } = await post('/entities/encryption-key', {
      session_id: sessionFor(BOB),
      encryption_public_key: '',
    });

    expect(status).toBe(400);
    expect(data.error).toMatch(/does not clear/i);
    expect(data.error).not.toMatch(/32 bytes/);
    expect(ctx.entities.getEncryptionKey(BOB)).toBe(X25519_KEY);
  });

  test('a missing key field is refused rather than clearing the key', async () => {
    // An absent field is not an instruction to delete. Clearing an entity's
    // encryption key silently downgrades every future message to it.
    const ctx = getDatabaseContext();
    ctx.entities.setEncryptionKey(BOB, X25519_KEY);

    const { status } = await post('/entities/encryption-key', {
      session_id: sessionFor(BOB),
    });

    expect(status).toBe(400);
    expect(ctx.entities.getEncryptionKey(BOB)).toBe(X25519_KEY);
  });
});

describe('the key is readable exactly where the entity already is', () => {
  test('it appears in the directory listing for a visible entity', async () => {
    const ctx = getDatabaseContext();
    ctx.entities.setEncryptionKey(BOB, X25519_KEY);

    const { status, data } = await post('/entities/list', {
      session_id: sessionFor(ALICE),
      entity_id: ALICE,
    });

    expect(status).toBe(200);
    const bob = (data.entities as any[]).find((e) => e.id === BOB);
    expect(bob).toBeDefined();
    expect(bob.encryption_public_key).toBe(X25519_KEY);
  });

  test('an entity in another account is not listed at all, key included', async () => {
    // The positive control for the test above: it must be possible for the
    // directory to CONTAIN an entity with a key, or "absent" proves nothing.
    // Above, BOB is present with his key. Here OUTSIDER is absent entirely, so
    // no separate key-visibility rule is needed or invented — visibility is
    // inherited, which is the point.
    const ctx = getDatabaseContext();
    ctx.entities.setEncryptionKey(OUTSIDER, OTHER_KEY);

    const { status, data } = await post('/entities/list', {
      session_id: sessionFor(ALICE),
      entity_id: ALICE,
    });

    expect(status).toBe(200);
    const ids = (data.entities as any[]).map((e) => e.id);
    expect(ids).toContain(BOB); // control: the listing is not simply empty
    expect(ids).not.toContain(OUTSIDER);
  });

  test('an entity that has published nothing reports null, not an empty string', async () => {
    const ctx = getDatabaseContext();
    const fresh = `fresh@${ACCOUNT}`;
    seedEntity(fresh, ACCOUNT);

    const { data } = await post('/entities/list', {
      session_id: sessionFor(ALICE),
      entity_id: ALICE,
    });

    const row = (data.entities as any[]).find((e) => e.id === fresh);
    expect(row).toBeDefined();
    // null means "cannot receive sealed messages yet". An empty string would be
    // a key that is present and useless, and a sender checking truthiness would
    // treat them the same — which is how a silent downgrade starts.
    expect(row.encryption_public_key).toBeNull();
    expect(ctx.entities.canReceiveSealed(fresh)).toBe(false);
  });
});
