import { test, expect, describe, beforeAll, afterAll } from 'bun:test';
import { startServer, stopServer } from '../http';
import { getDatabaseContext } from '../../db';
import { hashToken } from '../../auth/oauth';
import { generateKeyPair, bufferToBase64 } from '../../crypto/keys';
import { signVoucher, signRevocation, resolveEntityKey } from '../../crypto/voucher';

// ============================================================================
// Voucher routes — publishing and fetching account-signed key bindings.
//
// ⚠️ THE ROUTE DOES NOT VERIFY, AND THAT IS THE ANCHOR ARGUMENT RATHER THAN AN
// OMISSION. FAM cannot verify a voucher without the account public key, and it
// must never hold one: the anchor is the holder's own forge repository, which
// the relay cannot write to. A server that "helpfully" verified would need a
// key it should not have — and a peer that trusted the server's verification
// would be back to trusting the relay, which is the entire thing this defends
// against.
//
// So publishing accepts a well-formed record and THE RECIPIENT VERIFIES.
//
// ⚠️ AND FETCHING IS DELIBERATELY UNAUTHENTICATED-ish IN ONE SPECIFIC SENSE:
// the records are public by construction. A voucher discloses that an entity
// exists and which key it uses — both already visible to anyone who can message
// that entity. What it must NOT do is become a cross-account enumeration
// oracle, so fetch is scoped the way the directory is: you may ask about
// entities you can already see.
// ============================================================================

const TEST_PORT = 17941;
const TEST_HOST = '127.0.0.1';
const URL_BASE = `http://${TEST_HOST}:${TEST_PORT}`;
const TEST_SECRET = process.env.FAM_SERVER_SECRET!;

process.env.FAM_PORT = String(TEST_PORT);
process.env.FAM_HOST = TEST_HOST;

const ACCOUNT = 'voucherroutes@example.com';
const OTHER_ACCOUNT = 'stranger-vr@example.com';
const TOKEN = 'voucherroutes-token';
const OTHER_TOKEN = 'stranger-vr-token';

const ALICE = `alice@${ACCOUNT}`;
const OUTSIDER = `outsider@${OTHER_ACCOUNT}`;

type Endpoint = '/vouchers/publish' | '/vouchers/list';

let serverHandle: ReturnType<typeof startServer>;
let acct: { publicKey: string; privateKey: string };
let entityKey: string;

async function post(path: Endpoint, body: unknown): Promise<{ status: number; data: any }> {
  const res = await fetch(`${URL_BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, data: await res.json().catch(() => null) };
}

function sessionFor(entityId: string): string {
  return getDatabaseContext().sessions.create(entityId).id;
}

async function seedAccount(accountId: string, token: string): Promise<void> {
  const ctx = getDatabaseContext();
  ctx.db.prepare('INSERT OR IGNORE INTO accounts (id) VALUES (?)').run(accountId);
  ctx.db
    .prepare(
      `INSERT OR IGNORE INTO authorizations (id, account_id, server_id, token_hash)
       VALUES (?, ?, 'local', ?)`
    )
    .run(`auth-${accountId}`, accountId, await hashToken(token, TEST_SECRET));
}

function seedEntity(id: string, accountId: string, publicKey: string): void {
  getDatabaseContext()
    .db.prepare(
      `INSERT OR IGNORE INTO entities (id, account_id, type, public_key, capabilities)
       VALUES (?, ?, 'agent', ?, '{"can_send":true}')`
    )
    .run(id, accountId, publicKey);
}

async function voucher(sequence: number, over: Partial<{ entity: string; account: string }> = {}) {
  return signVoucher(acct.privateKey, {
    account: over.account ?? ACCOUNT,
    entity: over.entity ?? ALICE,
    entityPublicKey: entityKey,
    issuedAt: '2026-09-03T04:00:00.000Z',
    expiresAt: '2099-01-01T00:00:00.000Z',
    sequence,
  });
}

beforeAll(async () => {
  const a = await generateKeyPair();
  acct = { publicKey: bufferToBase64(a.publicKey), privateKey: bufferToBase64(a.privateKey) };
  entityKey = bufferToBase64((await generateKeyPair()).publicKey);

  await seedAccount(ACCOUNT, TOKEN);
  await seedAccount(OTHER_ACCOUNT, OTHER_TOKEN);
  seedEntity(ALICE, ACCOUNT, entityKey);
  seedEntity(OUTSIDER, OTHER_ACCOUNT, bufferToBase64((await generateKeyPair()).publicKey));

  serverHandle = startServer({ port: TEST_PORT, host: TEST_HOST });
});

afterAll(() => stopServer(serverHandle));

describe('POST /vouchers/publish', () => {
  test('an account can publish a voucher for its own entity', async () => {
    const { status, data } = await post('/vouchers/publish', {
      account_token: TOKEN,
      record: await voucher(1),
    });

    expect(status).toBe(201);
    expect(data.stored).toBe(true);
  });

  test('what was published comes back and still verifies', async () => {
    // The assertion a status code cannot make: not "the server said 201" but
    // "the crypto still accepts what it stored".
    const v = await voucher(2);
    await post('/vouchers/publish', { account_token: TOKEN, record: v });

    const { data } = await post('/vouchers/list', {
      session_id: sessionFor(ALICE),
      subject_entity_id: ALICE,
    });

    const resolved = await resolveEntityKey(acct.publicKey, ALICE, data.records);
    expect(resolved.status).toBe('valid');
    expect(resolved.status === 'valid' && resolved.entityPublicKey).toBe(entityKey);
  });

  test('a revocation publishes and resolves', async () => {
    const entity = `revoked@${ACCOUNT}`;
    seedEntity(entity, ACCOUNT, entityKey);

    await post('/vouchers/publish', {
      account_token: TOKEN,
      record: await voucher(1, { entity }),
    });
    await post('/vouchers/publish', {
      account_token: TOKEN,
      record: await signRevocation(acct.privateKey, {
        account: ACCOUNT,
        entity,
        revokedAt: '2026-09-03T05:00:00.000Z',
        sequence: 2,
      }),
    });

    const { data } = await post('/vouchers/list', {
      session_id: sessionFor(ALICE),
      subject_entity_id: entity,
    });
    expect((await resolveEntityKey(acct.publicKey, entity, data.records)).status).toBe('revoked');
  });

  test('an unauthenticated publish is refused', async () => {
    const { status } = await post('/vouchers/publish', { record: await voucher(9) });
    expect(status).toBe(401);
  });

  test('⚠️ publishing a record for ANOTHER account is refused', async () => {
    // The load-bearing authorization check. Without it, any account could
    // publish records naming any other account — and while a peer holding the
    // right account key would reject them on the signature, a peer that had NOT
    // yet obtained that key could be seeded with plausible-looking history.
    // Cheap to refuse here, and the refusal costs an attacker the ability to
    // pollute at all.
    const { status, data } = await post('/vouchers/publish', {
      account_token: OTHER_TOKEN,
      record: await voucher(1),
    });

    expect(status).toBe(403);
    expect(data.error).toMatch(/own account/i);
  });

  test('a malformed record is refused rather than stored', async () => {
    const { status } = await post('/vouchers/publish', {
      account_token: TOKEN,
      record: { nonsense: true },
    });
    expect(status).toBe(400);
  });

  test('a missing record is refused', async () => {
    const { status, data } = await post('/vouchers/publish', { account_token: TOKEN });
    expect(status).toBe(400);
    expect(data.error).toMatch(/record/i);
  });

  test('republishing the same record is idempotent, not an error', async () => {
    // A client that retries after a timeout must not get a 409 for succeeding
    // twice. The signature is the identity, so the second store is a no-op.
    const v = await voucher(42);
    const first = await post('/vouchers/publish', { account_token: TOKEN, record: v });
    const second = await post('/vouchers/publish', { account_token: TOKEN, record: v });

    expect(first.status).toBe(201);
    expect(second.status).toBe(201);
  });

  test('⚠️ the server does NOT verify the signature on the way in', async () => {
    // Deliberate, and it looks wrong. FAM cannot verify without the account
    // public key and must never hold one — a peer trusting the server's
    // verification is back to trusting the relay. A forged record is stored and
    // then refused by the only party whose opinion counts.
    const entity = `forged@${ACCOUNT}`;
    seedEntity(entity, ACCOUNT, entityKey);

    const { status } = await post('/vouchers/publish', {
      account_token: TOKEN,
      record: { ...(await voucher(1, { entity })), signature: 'AAAA' },
    });
    expect(status).toBe(201);

    const { data } = await post('/vouchers/list', {
      session_id: sessionFor(ALICE),
      subject_entity_id: entity,
    });
    expect((await resolveEntityKey(acct.publicKey, entity, data.records)).status).toBe('unknown');
  });
});

describe('POST /vouchers/list', () => {
  test('an unauthenticated fetch is refused', async () => {
    const { status } = await post('/vouchers/list', { subject_entity_id: ALICE });
    expect(status).toBe(401);
  });

  test('a missing entity_id is refused', async () => {
    const { status } = await post('/vouchers/list', { session_id: sessionFor(ALICE) });
    expect(status).toBe(400);
  });

  test('an entity with no records returns an empty list, not an error', async () => {
    const fresh = `fresh@${ACCOUNT}`;
    seedEntity(fresh, ACCOUNT, entityKey);

    const { status, data } = await post('/vouchers/list', {
      session_id: sessionFor(ALICE),
      subject_entity_id: fresh,
    });
    expect(status).toBe(200);
    expect(data.records).toEqual([]);
  });

  test('⚠️ an entity the caller cannot see is not readable', async () => {
    // Visibility is inherited from the directory rather than being a second
    // answer to "may A see B". A voucher discloses that an entity exists and
    // which key it uses; for an entity already in your directory that is
    // nothing new, and for one outside it, it would be an enumeration oracle.
    const { status } = await post('/vouchers/list', {
      session_id: sessionFor(ALICE),
      subject_entity_id: OUTSIDER,
    });

    expect(status).toBe(404);
  });

  test('the whole record set comes back, not just the newest', async () => {
    // ⚠️ Resolution needs every record: the answer depends on which one ranks
    // highest, and a partial set can only produce a STALE answer — which here
    // means trusting a key that was rotated or revoked. A route that returned
    // "the current voucher" would be making the resolution decision itself,
    // which is the recipient's to make.
    const entity = `multi@${ACCOUNT}`;
    seedEntity(entity, ACCOUNT, entityKey);

    for (const seq of [1, 2, 3]) {
      await post('/vouchers/publish', {
        account_token: TOKEN,
        record: await voucher(seq, { entity }),
      });
    }

    const { data } = await post('/vouchers/list', {
      session_id: sessionFor(ALICE),
      subject_entity_id: entity,
    });
    expect(data.records.length).toBe(3);
  });
});
