// Authentication Middleware for FAM Server

import type { DatabaseContext } from '../../db/transaction';
import { UnauthorizedError } from '../../types/errors';
import { hashToken } from '../../auth/oauth';

// ============================================================================
// Configuration
// ============================================================================

const SERVER_SECRET = process.env.FAM_SERVER_SECRET;
if (!SERVER_SECRET) {
  throw new Error('FAM_SERVER_SECRET environment variable is required');
}

// ============================================================================
// Token Validation
// ============================================================================

/**
 * Validate an account token and return the account ID.
 * Throws UnauthorizedError if token is invalid.
 */
export async function validateAccountToken(
  ctx: DatabaseContext,
  token: string
): Promise<string> {
  if (!token) {
    throw new UnauthorizedError('Missing account token');
  }
  
  // Hash the token to compare with stored hash
  const tokenHash = await hashToken(token, SERVER_SECRET!);
  
  // Look up authorization
  const auth = ctx.db.prepare(`
    SELECT account_id FROM authorizations 
    WHERE token_hash = ? 
    AND revoked_at IS NULL 
    AND (expires_at IS NULL OR expires_at > datetime('now'))
  `).get(tokenHash) as { account_id: string } | undefined;
  
  if (!auth) {
    throw new UnauthorizedError('Invalid or expired account token');
  }
  
  return auth.account_id;
}

// ============================================================================
// Entity Session Enforcement
// ============================================================================

const SESSION_MAX_IDLE_MS = 60 * 1000;

export interface EntityAuth {
  /** The acting entity, taken from the SESSION — never from the request body. */
  entityId: string;
  sessionId: string;
  /** The parsed request body, so handlers do not re-read the stream. */
  body: any;
}

/**
 * Authenticate an entity-scoped request and return the acting entity.
 *
 * The entity id is read from the session, not the body. Previously these
 * routes trusted a body-supplied `entity_id`, which made the whole
 * three-layer auth model decorative — the permission matrix, channel roles
 * and cross-account grants all computed correct answers about an unverified
 * subject. Forging a message required no token, session or key.
 *
 * A body-supplied `entity_id` is still accepted, but only as a redundant
 * assertion that must agree with the session. Disagreement is rejected rather
 * than ignored: silently overriding it would hide client bugs, and a client
 * that thinks it is acting as someone else should be told.
 */
export async function requireEntitySession(
  ctx: DatabaseContext,
  req: Request
): Promise<EntityAuth> {
  const body = (await req.json().catch(() => ({}))) as any;

  // Deliberately body-only, NOT the Authorization header. That header already
  // carries the ACCOUNT token on /accounts/* and /admin/api/*, and the CLI sets
  // it on every request. Accepting it here too would mean a client sending its
  // account token to an entity route got "invalid session" instead of a useful
  // error — two different credentials in one slot, distinguishable only by
  // which route you happened to hit.
  const sessionId = body?.session_id;

  if (!sessionId) {
    throw new UnauthorizedError('Missing session_id');
  }

  const session = ctx.sessions.getById(sessionId);
  if (!session) {
    throw new UnauthorizedError('Invalid session');
  }

  const lastHeartbeat = new Date(session.last_heartbeat).getTime();
  if (Date.now() - lastHeartbeat > SESSION_MAX_IDLE_MS) {
    throw new UnauthorizedError('Session expired');
  }

  if (body?.entity_id != null && body.entity_id !== session.entity_id) {
    throw new UnauthorizedError('Session does not own the requested entity_id');
  }

  return { entityId: session.entity_id, sessionId, body };
}

/**
 * Extract token from Authorization header.
 */
export function extractBearerToken(req: Request): string | null {
  const authHeader = req.headers.get('Authorization');
  if (!authHeader) {
    return null;
  }
  
  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return null;
  }
  
  return parts[1] ?? null;
}
