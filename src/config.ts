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
