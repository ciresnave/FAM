// Browser session lifecycle for the admin console.
//
// WHY A TOKEN EXCHANGE rather than a second OAuth redirect: the OAuth flow
// already ends by issuing an account token, and adding a browser-specific
// callback would mean a second registered redirect_uri at every provider plus
// a column recording which flow a pending state belongs to. The console
// instead trades the token it already has for a cookie. One credential
// converts into another; no provider configuration changes.
//
// The cookie is HttpOnly, so the SPA can never read it. The CSRF token IS
// readable — it is returned in the response body and held in memory — because
// a value the attacker's page cannot read is exactly what makes it a proof of
// same-origin. If it were also a cookie it would be sent automatically and
// prove nothing.

import type { DatabaseContext } from '../../db/transaction';
import type { Route } from './index';
import { validateAccountToken, extractBearerToken } from '../middleware/auth';
import {
  requireAdminSession,
  ADMIN_COOKIE,
  parseCookies,
} from '../middleware/adminAuth';
import { ADMIN_SESSION_TTL_HOURS } from '../../db/repositories/adminSession';
import { adminAllowedOrigins } from '../../config';

function json(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: { 'Content-Type': 'application/json', ...(init.headers ?? {}) },
  });
}

/**
 * Serialise the session cookie.
 *
 * `Secure` is set only for https, because setting it unconditionally makes the
 * cookie unusable over http and the console is developed against localhost.
 * SameSite=Strict is a real second line behind the CSRF token: it stops the
 * browser attaching this cookie to cross-site requests at all.
 */
function sessionCookie(req: Request, id: string, maxAgeSeconds: number): string {
  const secure = new URL(req.url).protocol === 'https:' ? '; Secure' : '';
  return (
    `${ADMIN_COOKIE}=${id}; HttpOnly; SameSite=Strict; Path=/admin; ` +
    `Max-Age=${maxAgeSeconds}${secure}`
  );
}

function clearedCookie(req: Request): string {
  return sessionCookie(req, '', 0);
}

export function adminSessionRoutes(ctx: DatabaseContext): Route[] {
  return [
    // POST /admin/api/session/create
    // Exchange an account token for a browser session.
    {
      method: 'POST',
      pattern: '/admin/api/session/create',
      handler: async (req) => {
        const body = (await req.json().catch(() => ({}))) as any;
        const token = extractBearerToken(req) ?? body?.account_token;
        const accountId = await validateAccountToken(ctx, token);

        const session = ctx.adminSessions.create(accountId);

        return json(
          {
            account_id: accountId,
            csrf_token: session.csrf_token,
            expires_at: session.expires_at,
          },
          {
            status: 201,
            headers: {
              'Set-Cookie': sessionCookie(
                req,
                session.id,
                ADMIN_SESSION_TTL_HOURS * 3600
              ),
            },
          }
        );
      },
    },

    // GET /admin/api/session/current
    // Who am I, and what is my CSRF token? The SPA calls this on load: the
    // cookie survives a refresh but the in-memory CSRF token does not.
    {
      method: 'GET',
      pattern: '/admin/api/session/current',
      handler: async (req) => {
        const auth = requireAdminSession(ctx, req, adminAllowedOrigins());
        return json({
          account_id: auth.accountId,
          csrf_token: auth.session.csrf_token,
          expires_at: auth.session.expires_at,
        });
      },
    },

    // POST /admin/api/session/destroy
    // Log out. Deletes the row, so the cookie is dead even if the browser
    // keeps it — clearing the cookie alone would leave a usable session id in
    // anything that captured it.
    {
      method: 'POST',
      pattern: '/admin/api/session/destroy',
      handler: async (req) => {
        const auth = requireAdminSession(ctx, req, adminAllowedOrigins());
        ctx.adminSessions.delete(auth.session.id);
        return json(
          { ok: true },
          { headers: { 'Set-Cookie': clearedCookie(req) } }
        );
      },
    },
  ];
}

/**
 * True when the request carries an admin session cookie, and so should be
 * authenticated as a browser (with CSRF enforced) rather than by bearer token.
 */
export function hasAdminCookie(req: Request): boolean {
  return parseCookies(req.headers.get('Cookie')).has(ADMIN_COOKIE);
}
