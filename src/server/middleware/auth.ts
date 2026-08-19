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

/**
 * Validate an entity token (session-based).
 * Returns the entity ID if valid.
 */
export function validateEntitySession(
  ctx: DatabaseContext,
  entityId: string,
  sessionId: string
): string {
  if (!entityId || !sessionId) {
    throw new UnauthorizedError('Missing entity_id or session_id');
  }
  
  const session = ctx.sessions.getById(sessionId);
  if (!session || session.entity_id !== entityId) {
    throw new UnauthorizedError('Invalid session');
  }
  
  // Check if session is still active (heartbeat within last 60 seconds)
  const lastHeartbeat = new Date(session.last_heartbeat).getTime();
  const now = Date.now();
  if (now - lastHeartbeat > 60 * 1000) {
    throw new UnauthorizedError('Session expired');
  }
  
  return entityId;
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
