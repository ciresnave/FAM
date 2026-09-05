// Shared endpoint defaults.
//
// These were previously written out by hand in fourteen places across the
// server, the MCP adapter and the CLI. That duplication is why FAM and the
// claude-peers broker both defaulted to 7899 and could not run side by side —
// changing the number in one file would have left the others behind, and
// nothing would have noticed. `src/__tests__/config.test.ts` fails if the
// broker port reappears as a literal anywhere under src/.

/**
 * The port the claude-peers broker binds (`CLAUDE_PEERS_PORT`, default 7899).
 *
 * FAM must not default to it. During a migration both need to run at once —
 * a cutover with no ability to run old and new together is not a migration,
 * it is a single attempt with no back-out.
 */
export const CLAUDE_PEERS_BROKER_PORT = 7899;

/** FAM's default listen port. Deliberately adjacent to, and distinct from, the broker's. */
export const DEFAULT_PORT = 7900;

export const DEFAULT_HOST = '127.0.0.1';

export const DEFAULT_SERVER_URL = `http://${DEFAULT_HOST}:${DEFAULT_PORT}`;
export const DEFAULT_WS_URL = `ws://${DEFAULT_HOST}:${DEFAULT_PORT}/ws`;

/**
 * Origins the admin console may be called from.
 *
 * `FAM_ADMIN_ORIGINS` (comma-separated) when set, otherwise the server's own
 * origin. Used only to REFUSE a mismatched Origin header — absence is allowed,
 * because same-origin form posts and older clients omit it legitimately and an
 * attacker can omit it just as easily. See `middleware/adminAuth.ts`.
 */
export function adminAllowedOrigins(): string[] {
  const configured = process.env.FAM_ADMIN_ORIGINS;
  if (configured) {
    return configured.split(',').map(o => o.trim()).filter(Boolean);
  }
  const port = process.env.FAM_PORT ?? String(DEFAULT_PORT);
  const host = process.env.FAM_HOST ?? DEFAULT_HOST;
  return [`http://${host}:${port}`, `http://localhost:${port}`];
}


/**
 * How many days of message history to keep. Zero means keep everything.
 *
 * RULED BY CIRESNAVE 2026-09-02: no retention. DESIGN.md's Open Question 4
 * ("how long to keep message history?") is closed, and it had been open since
 * the document was written.
 *
 * THIS IS A CHANGE, NOT A CONFIRMATION. The default was 30 days and the sweep
 * ran on a timer, so delivered messages HAVE been deleted after a month. His
 * reading was that retention had always been off; it had not, and the
 * difference is worth naming rather than quietly implementing the ruling as
 * though nothing changed.
 *
 * WHY OFF IS RIGHT REGARDLESS: storage is not the pressure — the predecessor
 * carried 6,000 messages and 13 MB in a month — and silently deleting history a
 * person can still remember is a surprising default. An operator who wants a
 * lifetime can set one; nobody has to opt IN to keeping their own data.
 *
 * The value is still honoured when set, so this is a default change and not a
 * removal of the capability.
 */
export function messageRetentionDays(): number {
  const raw = process.env.FAM_MESSAGE_RETENTION_DAYS;
  if (raw === undefined || raw === '') return 0;

  const days = parseInt(raw, 10);
  // A malformed value keeps everything rather than guessing a number. Deleting
  // on the strength of a typo is the one outcome with no undo.
  return Number.isFinite(days) && days > 0 ? days : 0;
}
