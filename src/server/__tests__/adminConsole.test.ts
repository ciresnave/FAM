import { test, expect, describe, beforeAll, afterAll } from 'bun:test';
import { startServer, stopServer } from '../http';
import { getDatabaseContext } from '../../db';
import { hashToken } from '../../auth/oauth';
import { ADMIN_COOKIE, CSRF_HEADER } from '../middleware/adminAuth';

// ============================================================================
// The admin console's browser session, exercised through the REAL HTTP stack.
//
// The middleware has its own unit tests. This file exists because those prove
// something narrower than they look: they prove `requireAdminSession` refuses,
// not that any ROUTE calls it. A middleware that refuses perfectly and is
// wired to nothing passes every one of them.
//
// So the load-bearing test here is the CSRF one on a real WRITE route. That is
// the assertion that fails if the cookie path is added to the admin API and
// the CSRF check is not.
// ============================================================================

const TEST_PORT = 17901;
const TEST_HOST = '127.0.0.1';
const URL_BASE = `http://${TEST_HOST}:${TEST_PORT}`;
const SECRET = process.env.FAM_SERVER_SECRET!;

const ACCOUNT = 'console@example.com';
const TOKEN = 'console-account-token';
const OTHER_ACCOUNT = 'other-console@example.com';
const COMPARE_ACCOUNT = 'compare-console@example.com';

let cookie: string;
let csrf: string;

async function post(path: string, body: unknown, headers: Record<string, string> = {}) {
  const res = await fetch(`${URL_BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body ?? {}),
  });
  const json = (await res.json().catch(() => ({}))) as any;
  return { status: res.status, res, json };
}

async function get(path: string, headers: Record<string, string> = {}) {
  const res = await fetch(`${URL_BASE}${path}`, { headers });
  const json = (await res.json().catch(() => ({}))) as any;
  return { status: res.status, res, json };
}

function cookieFrom(setCookie: string): string {
  const value = setCookie.split(`${ADMIN_COOKIE}=`)[1]!.split(';')[0];
  return `${ADMIN_COOKIE}=${value}`;
}

beforeAll(async () => {
  const ctx = getDatabaseContext();
  for (const id of [ACCOUNT, OTHER_ACCOUNT, COMPARE_ACCOUNT]) {
    ctx.db.prepare('INSERT OR IGNORE INTO accounts (id) VALUES (?)').run(id);
  }
  ctx.db
    .prepare(
      `INSERT OR IGNORE INTO authorizations (id, account_id, server_id, token_hash)
       VALUES (?, ?, 'local', ?)`
    )
    .run('console-auth-1', ACCOUNT, await hashToken(TOKEN, SECRET));

  // An entity for this account to grant away.
  ctx.db
    .prepare(
      `INSERT OR IGNORE INTO entities (id, account_id, type, public_key, capabilities)
       VALUES (?, ?, 'agent', 'pk', '{"can_send":true}')`
    )
    .run(`shared@${ACCOUNT}`, ACCOUNT);
  // A second entity, so the indistinguishability comparison cannot collide
  // with a grant an earlier test already created.
  ctx.db
    .prepare(
      `INSERT OR IGNORE INTO entities (id, account_id, type, public_key, capabilities)
       VALUES (?, ?, 'agent', 'pk', '{"can_send":true}')`
    )
    .run(`compare@${ACCOUNT}`, ACCOUNT);

  startServer({ port: TEST_PORT, host: TEST_HOST });
  await Bun.sleep(150);
});

afterAll(() => stopServer());

// ---------------------------------------------------------------------------
// REFUSALS FIRST.
// ---------------------------------------------------------------------------

describe('session exchange refuses', () => {
  test('no account token at all', async () => {
    const { status } = await post('/admin/api/session/create', {});
    expect(status).toBe(401);
  });

  test('a bogus account token', async () => {
    const { status } = await post('/admin/api/session/create', {
      account_token: 'not-a-real-token',
    });
    expect(status).toBe(401);
  });

  test('reading the current session with no cookie', async () => {
    const { status } = await get('/admin/api/session/current');
    expect(status).toBe(401);
  });

  test('a cookie naming a session that does not exist', async () => {
    const { status } = await get('/admin/api/session/current', {
      Cookie: `${ADMIN_COOKIE}=00000000-0000-4000-8000-000000000000`,
    });
    expect(status).toBe(401);
  });
});

// ---------------------------------------------------------------------------
// The exchange itself.
// ---------------------------------------------------------------------------

describe('exchanging an account token for a browser session', () => {
  test('returns a csrf token and sets an HttpOnly cookie', async () => {
    const { status, res, json } = await post('/admin/api/session/create', {
      account_token: TOKEN,
    });

    expect(status).toBe(201);
    expect(json.account_id).toBe(ACCOUNT);
    expect(typeof json.csrf_token).toBe('string');

    const setCookie = res.headers.get('Set-Cookie') ?? '';
    expect(setCookie).toContain(`${ADMIN_COOKIE}=`);
    // HttpOnly is the point: script on the page must never read this value.
    expect(setCookie).toContain('HttpOnly');
    expect(setCookie).toContain('SameSite=Strict');

    cookie = cookieFrom(setCookie);
    csrf = json.csrf_token;
  });

  test('the CSRF token is NOT delivered as a cookie', async () => {
    // If it were, the browser would attach it automatically and it would prove
    // nothing about who sent the request.
    const { res } = await post('/admin/api/session/create', { account_token: TOKEN });
    expect(res.headers.get('Set-Cookie') ?? '').not.toContain('csrf');
  });

  test('the session identifies the account on a subsequent request', async () => {
    const { status, json } = await get('/admin/api/session/current', { Cookie: cookie });
    expect(status).toBe(200);
    expect(json.account_id).toBe(ACCOUNT);
  });
});

// ---------------------------------------------------------------------------
// THE LOAD-BEARING TESTS. A cookie is attached by the browser to any request
// any page can cause, so a write authenticated by cookie alone is forgeable.
// ---------------------------------------------------------------------------

describe('CSRF is enforced on the real admin API, not just in middleware', () => {
  test('a WRITE with a valid cookie but NO csrf header is refused', async () => {
    const { status } = await post(
      '/admin/api/grants',
      { grantee_account_id: OTHER_ACCOUNT, entity_id: `shared@${ACCOUNT}` },
      { Cookie: cookie }
    );
    expect(status).toBe(403);
  });

  test('a WRITE with a WRONG csrf header is refused', async () => {
    const { status } = await post(
      '/admin/api/grants',
      { grantee_account_id: OTHER_ACCOUNT, entity_id: `shared@${ACCOUNT}` },
      { Cookie: cookie, [CSRF_HEADER]: 'not-the-token' }
    );
    expect(status).toBe(403);
  });

  test('a cross-origin write is refused even WITH the csrf token', async () => {
    const { status } = await post(
      '/admin/api/grants',
      { grantee_account_id: OTHER_ACCOUNT, entity_id: `shared@${ACCOUNT}` },
      { Cookie: cookie, [CSRF_HEADER]: csrf, Origin: 'https://evil.example.com' }
    );
    expect(status).toBe(403);
  });

  // Only meaningful because the three refusals above are established.
  test('the same write SUCCEEDS with the csrf token', async () => {
    const { status } = await post(
      '/admin/api/grants',
      { grantee_account_id: OTHER_ACCOUNT, entity_id: `shared@${ACCOUNT}` },
      { Cookie: cookie, [CSRF_HEADER]: csrf }
    );
    expect(status).toBeLessThan(300);
  });

  // A read that is SHAPED as a POST is still CSRF-checked, and that is the
  // right default rather than a wart. The middleware sees a method, not an
  // intention: every admin read here is POST /.../list, and exempting them
  // would mean maintaining a list of "POSTs that are really reads" — which is
  // a second place to be wrong, and it fails open.
  //
  // The console is unaffected: GET /admin/api/session/current is a genuine GET,
  // needs no token, and is where the SPA gets the token for everything else.
  test('a POST-shaped READ is ALSO refused without a csrf token', async () => {
    const { status } = await post('/admin/api/grants/list', {}, { Cookie: cookie });
    expect(status).toBe(403);
  });

  test('the same read succeeds with the csrf token', async () => {
    const { status } = await post(
      '/admin/api/grants/list',
      {},
      { Cookie: cookie, [CSRF_HEADER]: csrf }
    );
    expect(status).toBe(200);
  });

  // The bootstrap path must work with no token, or the console can never
  // acquire one after a refresh.
  test('the GET bootstrap needs no csrf token', async () => {
    const { status } = await get('/admin/api/session/current', { Cookie: cookie });
    expect(status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// Bearer tokens must keep working — the console is additive, not a replacement.
// ---------------------------------------------------------------------------

describe('the bearer-token path still works', () => {
  test('a write authenticated by bearer needs no csrf token', async () => {
    const { status } = await post('/admin/api/grants/list', { account_token: TOKEN });
    expect(status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// Logout must kill the ROW, not just the cookie.
// ---------------------------------------------------------------------------

describe('logout', () => {
  test('destroys the session so a captured cookie is dead', async () => {
    const fresh = await post('/admin/api/session/create', { account_token: TOKEN });
    const c = cookieFrom(fresh.res.headers.get('Set-Cookie')!);
    const token = fresh.json.csrf_token;

    expect((await get('/admin/api/session/current', { Cookie: c })).status).toBe(200);

    const out = await post('/admin/api/session/destroy', {}, { Cookie: c, [CSRF_HEADER]: token });
    expect(out.status).toBe(200);

    // The cookie is still in this test's hands. It must no longer work.
    expect((await get('/admin/api/session/current', { Cookie: c })).status).toBe(401);
  });
});

// ---------------------------------------------------------------------------
// PENDING INVITES, AT THE API. Migration v10 dropped the three foreign keys so
// a grant or rule MAY name a subject that does not exist — CireSnave's ruling,
// on the grounds that "account A should be able to set up grants and rules for
// agents that account B hasn't gotten around to creating yet."
//
// The v10 tests proved this against the REPOSITORY. That is one level below
// the claim: the routes kept their own `ctx.accounts.exists()` checks, so the
// database permitted a pending grant and the API went on refusing it with 404.
// The product behaviour was unchanged and the tests were green.
//
// These assert it where a user meets it.
// ---------------------------------------------------------------------------

describe('a grant may name an account that does not exist', () => {
  const STRANGER = 'not-a-user-yet@example.com';

  test('creating it succeeds rather than 404ing', async () => {
    const { status } = await post(
      '/admin/api/grants',
      { grantee_account_id: STRANGER, entity_id: `shared@${ACCOUNT}` },
      { Cookie: cookie, [CSRF_HEADER]: csrf }
    );
    expect(status).toBe(201);
  });

  // THE ORACLE CLOSURE, asserted as a comparison. The point is not that both
  // succeed — it is that the caller cannot tell an account that exists from one
  // that does not, which is what makes the address unlearnable.
  test('the response is indistinguishable from granting to a known account', async () => {
    const known = await post(
      '/admin/api/grants',
      { grantee_account_id: COMPARE_ACCOUNT, entity_id: `compare@${ACCOUNT}`, capabilities: { can_send: true } },
      { Cookie: cookie, [CSRF_HEADER]: csrf }
    );
    const unknown = await post(
      '/admin/api/grants',
      { grantee_account_id: 'also-nobody@example.com', entity_id: `compare@${ACCOUNT}`, capabilities: { can_send: true } },
      { Cookie: cookie, [CSRF_HEADER]: csrf }
    );

    expect(unknown.status).toBe(known.status);
    expect(Object.keys(unknown.json.grant).sort()).toEqual(Object.keys(known.json.grant).sort());
  });

  test('a rule may name a source account that does not exist', async () => {
    const { status } = await post(
      '/admin/api/permissions',
      {
        target_type: 'all',
        source_type: 'account',
        source_account_id: 'blocked-before-they-exist@example.com',
        action: 'deny',
      },
      { Cookie: cookie, [CSRF_HEADER]: csrf }
    );
    expect(status).toBe(201);
  });

  // The listing must not become the oracle the create path stopped being.
  // Nothing in a grant row may report whether the grantee has an account.
  test('listing grants does not disclose whether the grantee exists', async () => {
    const { json } = await post(
      '/admin/api/grants/list',
      { direction: 'given' },
      { Cookie: cookie, [CSRF_HEADER]: csrf }
    );
    const rows: any[] = json.grants;
    const stranger = rows.find(g => g.grantee_account_id === STRANGER);
    const real = rows.find(g => g.grantee_account_id === OTHER_ACCOUNT);

    expect(stranger).toBeDefined();
    expect(real).toBeDefined();
    // Same fields, same shape. A "pending" flag here would re-open the oracle
    // one step removed: create a grant, list it, learn whether the address has
    // an account.
    expect(Object.keys(stranger).sort()).toEqual(Object.keys(real).sort());
  });
});
