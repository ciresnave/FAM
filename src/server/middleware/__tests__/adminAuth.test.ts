import { test, expect, describe, beforeAll } from 'bun:test';
import {
  requireAdminSession,
  parseCookies,
  ADMIN_COOKIE,
  CSRF_HEADER,
} from '../adminAuth';
import { getDatabaseContext } from '../../../db';
import type { DatabaseContext } from '../../../db/transaction';

// ============================================================================
// Browser session auth for the admin console.
//
// THE NEGATIVE CONTROLS COME FIRST, DELIBERATELY. A cookie-auth middleware that
// accepts a valid request proves nothing about whether it refuses a forged one,
// and a CSRF check that silently passes everything is indistinguishable from
// one that works. So every rejection is asserted before the first acceptance.
//
// The threat is new to FAM. The entity API is bearer-token only, and a bearer
// token is attached deliberately by a client. A COOKIE is attached
// automatically by the browser to any request any page can cause — so this
// session is reachable from every site the account holder visits.
// ============================================================================

const ACCOUNT = 'adminauth@example.com';
const ORIGIN = 'http://localhost:3000';
const ALLOWED = [ORIGIN];

let ctx: DatabaseContext;
let sessionId: string;
let csrf: string;

function req(opts: {
  method?: string;
  cookie?: string | null;
  csrf?: string | null;
  origin?: string | null;
}): Request {
  const headers = new Headers();
  if (opts.cookie !== null && opts.cookie !== undefined) headers.set('Cookie', opts.cookie);
  if (opts.csrf !== null && opts.csrf !== undefined) headers.set(CSRF_HEADER, opts.csrf);
  if (opts.origin !== null && opts.origin !== undefined) headers.set('Origin', opts.origin);

  return new Request('http://localhost:7900/admin/api/grants', {
    method: opts.method ?? 'POST',
    headers,
  });
}

beforeAll(() => {
  ctx = getDatabaseContext();
  ctx.db.prepare('INSERT OR IGNORE INTO accounts (id) VALUES (?)').run(ACCOUNT);
  const session = ctx.adminSessions.create(ACCOUNT);
  sessionId = session.id;
  csrf = session.csrf_token;
});

// ---------------------------------------------------------------------------
// NEGATIVE CONTROLS — every one of these must refuse.
// ---------------------------------------------------------------------------

describe('refusals', () => {
  test('no cookie at all', () => {
    expect(() => requireAdminSession(ctx, req({ cookie: null, csrf, origin: ORIGIN }), ALLOWED)).toThrow();
  });

  test('a cookie naming a session that does not exist', () => {
    expect(() =>
      requireAdminSession(
        ctx,
        req({ cookie: `${ADMIN_COOKIE}=00000000-0000-4000-8000-000000000000`, csrf, origin: ORIGIN }),
        ALLOWED
      )
    ).toThrow();
  });

  // THE CSRF CONTROL. A valid session cookie is present — exactly what a
  // browser would send from an attacker's page — and the request must still be
  // refused, because the attacker cannot read the token.
  test('valid session cookie but NO csrf token', () => {
    expect(() =>
      requireAdminSession(ctx, req({ cookie: `${ADMIN_COOKIE}=${sessionId}`, csrf: null, origin: ORIGIN }), ALLOWED)
    ).toThrow();
  });

  test('valid session cookie but WRONG csrf token', () => {
    expect(() =>
      requireAdminSession(
        ctx,
        req({ cookie: `${ADMIN_COOKIE}=${sessionId}`, csrf: 'not-the-token', origin: ORIGIN }),
        ALLOWED
      )
    ).toThrow();
  });

  // A CSRF token belonging to a DIFFERENT session must not work either —
  // otherwise any account holder could forge against any other.
  test("another session's csrf token", () => {
    const other = ctx.adminSessions.create(ACCOUNT);
    expect(() =>
      requireAdminSession(
        ctx,
        req({ cookie: `${ADMIN_COOKIE}=${sessionId}`, csrf: other.csrf_token, origin: ORIGIN }),
        ALLOWED
      )
    ).toThrow();
  });

  test('a cross-origin request, even with a correct csrf token', () => {
    expect(() =>
      requireAdminSession(
        ctx,
        req({ cookie: `${ADMIN_COOKIE}=${sessionId}`, csrf, origin: 'https://evil.example.com' }),
        ALLOWED
      )
    ).toThrow();
  });

  test('an expired session', () => {
    const expired = ctx.adminSessions.create(ACCOUNT, -1); // already past
    expect(() =>
      requireAdminSession(
        ctx,
        req({ cookie: `${ADMIN_COOKIE}=${expired.id}`, csrf: expired.csrf_token, origin: ORIGIN }),
        ALLOWED
      )
    ).toThrow();
  });
});

// ---------------------------------------------------------------------------
// POSITIVE — only meaningful because the refusals above are established.
// ---------------------------------------------------------------------------

describe('acceptance', () => {
  test('valid cookie, matching csrf, allowed origin', () => {
    const auth = requireAdminSession(
      ctx,
      req({ cookie: `${ADMIN_COOKIE}=${sessionId}`, csrf, origin: ORIGIN }),
      ALLOWED
    );
    expect(auth.accountId).toBe(ACCOUNT);
    expect(auth.session.id).toBe(sessionId);
  });

  // A GET carries no state change, and requiring a header on it would break
  // loading the console at all — the first request has nowhere to get a token.
  test('a GET is accepted without a csrf token', () => {
    const auth = requireAdminSession(
      ctx,
      req({ method: 'GET', cookie: `${ADMIN_COOKIE}=${sessionId}`, csrf: null, origin: ORIGIN }),
      ALLOWED
    );
    expect(auth.accountId).toBe(ACCOUNT);
  });

  // A same-origin form post from an old browser may omit Origin entirely.
  // Absent is not the same as wrong; only a MISMATCH is refused.
  test('a request with no Origin header at all is accepted', () => {
    const auth = requireAdminSession(
      ctx,
      req({ cookie: `${ADMIN_COOKIE}=${sessionId}`, csrf, origin: null }),
      ALLOWED
    );
    expect(auth.accountId).toBe(ACCOUNT);
  });
});

describe('cookie parsing', () => {
  test('reads one cookie among several', () => {
    const jar = parseCookies(`other=1; ${ADMIN_COOKIE}=abc; another=2`);
    expect(jar.get(ADMIN_COOKIE)).toBe('abc');
  });

  test('an absent header is empty rather than an error', () => {
    expect(parseCookies(null).size).toBe(0);
  });
});
