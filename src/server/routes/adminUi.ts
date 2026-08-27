// Serves the admin console page itself.
//
// PUBLIC by design: this is the sign-in screen. It contains no account data —
// every byte of that arrives later, from /admin/api/*, which requires a
// session. Gating the page itself would mean gating the only place a person
// can sign in.
//
// Served as a single self-contained file rather than a bundled React app. The
// plan of record said "React SPA (HTML imports, no vite)", and the deviation is
// deliberate: React is not a dependency of this project (there are two, and
// both are runtime protocol libraries), so a React console would add a
// dependency and a bundling step to the server's start path — including inside
// the test suite, which boots the real server. The console is four read screens
// and two forms. It does not earn that.

import type { Route } from './index';

const CONSOLE_HTML = new URL('../../admin/console.html', import.meta.url);

export function adminUiRoutes(): Route[] {
  return [
    {
      method: 'GET',
      pattern: '/admin',
      handler: async () => {
        const file = Bun.file(CONSOLE_HTML);
        if (!(await file.exists())) {
          return new Response('Admin console not found', { status: 404 });
        }
        return new Response(file, {
          headers: {
            'Content-Type': 'text/html; charset=utf-8',
            // The page is the shell only; it holds no account data, but it
            // should not be cached across a deploy either.
            'Cache-Control': 'no-cache',
            // Defence in depth for a page that renders identifiers supplied by
            // other accounts. Everything it needs is inline, so the policy can
            // be tight without breaking it.
            'Content-Security-Policy':
              "default-src 'none'; " +
              "style-src 'unsafe-inline'; " +
              "script-src 'unsafe-inline'; " +
              "connect-src 'self'; " +
              "form-action 'none'; " +
              "base-uri 'none'; " +
              "frame-ancestors 'none'",
            'X-Content-Type-Options': 'nosniff',
            'Referrer-Policy': 'no-referrer',
          },
        });
      },
    },
  ];
}
