// Browser session authentication for the admin console.
//
// WHY THIS FILE EXISTS AT ALL, and why it is not just `requireEntitySession`
// with cookies: the entity API is bearer-token only. A bearer token is attached
// deliberately by a client. A COOKIE is attached automatically by the browser,
// to any request any page can cause — so a session identified by a cookie is
// reachable by every site the account holder visits. That is CSRF, and FAM has
// never been exposed to it.

import type { DatabaseContext } from '../../db/transaction';
import type { AdminSession } from '../../db/repositories/adminSession';
import { UnauthorizedError, ForbiddenError } from '../../types/errors';
import { logger } from '../../utils/logger';

/** Name of the session cookie. */
export const ADMIN_COOKIE = 'fam_admin_session';

/** Header carrying the CSRF token on state-changing requests. */
export const CSRF_HEADER = 'x-fam-csrf';

export interface AdminAuth {
  accountId: string;
  session: AdminSession;
}

/**
 * Parse a Cookie header into a map. Returns an empty map when absent.
 */
export function parseCookies(header: string | null): Map<string, string> {
  const out = new Map<string, string>();
  if (!header) return out;

  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    const name = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (name) out.set(name, value);
  }
  return out;
}

/** Methods that cannot change state, and so need no CSRF token. */
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Authenticate an admin-console request.
 *
 * Three independent checks, because each covers a case the others do not:
 *
 *  1. SESSION COOKIE — who you are. Alone it is forgeable cross-site, because
 *     the browser sends it whether or not the page asking is ours.
 *  2. CSRF TOKEN on state-changing methods — proves the caller could READ our
 *     response at some point, which a cross-site attacker cannot do. This is
 *     the check the cookie cannot make for itself.
 *  3. ORIGIN, when present — defence in depth. A MISMATCH is refused; ABSENCE
 *     is not, because same-origin form posts and older clients legitimately
 *     omit it, and refusing those would break the console while stopping no
 *     attacker who can simply omit the header too.
 *
 * Note 2 and 3 are not redundant: Origin can be absent, and a token can leak.
 */
export function requireAdminSession(
  ctx: DatabaseContext,
  req: Request,
  allowedOrigins: string[]
): AdminAuth {
  const cookies = parseCookies(req.headers.get('Cookie'));
  const sessionId = cookies.get(ADMIN_COOKIE);

  if (!sessionId) {
    throw new UnauthorizedError('No admin session cookie');
  }

  // getActive, not getById: an expired row still exists and would otherwise
  // authenticate.
  const session = ctx.adminSessions.getActive(sessionId);
  if (!session) {
    throw new UnauthorizedError('Admin session is invalid or expired');
  }

  const origin = req.headers.get('Origin');
  if (origin !== null && !allowedOrigins.includes(origin)) {
    throw new ForbiddenError(`Origin ${origin} is not allowed`);
  }

  const unsafe = !SAFE_METHODS.has(req.method.toUpperCase());

  // Absence is allowed (see above) but NOT ignored. Modern browsers send Origin
  // on all POSTs including same-origin, so absence increasingly means "not a
  // browser" — an older client, a direct API call, or a script. That is not
  // refusable, for the reason above, but a rise in Origin-absent authenticated
  // writes is a signal about who is calling the console, and it is better to
  // have it before it is wanted urgently.
  if (unsafe && origin === null) {
    logger.info('Admin write with no Origin header', {
      accountId: session.account_id,
      method: req.method,
      path: new URL(req.url).pathname,
    });
  }

  if (unsafe) {
    const presented = req.headers.get(CSRF_HEADER);
    if (!presented || presented !== session.csrf_token) {
      throw new ForbiddenError(
        'Missing or invalid CSRF token. State-changing admin requests must send ' +
          `the session's CSRF token in the ${CSRF_HEADER} header.`
      );
    }
  }

  return { accountId: session.account_id, session };
}

/**
 * True when the request carries an admin session cookie, and so should be
 * authenticated as a browser — with CSRF enforced — rather than by bearer
 * token.
 */
export function hasAdminCookie(req: Request): boolean {
  return parseCookies(req.headers.get('Cookie')).has(ADMIN_COOKIE);
}
