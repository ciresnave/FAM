// Request ID Middleware for FAM Server
//
// Generates a unique request ID for each request, adds it to response headers,
// and makes it available for logging correlation.

import { randomBytes } from 'crypto';

// ============================================================================
// Types
// ============================================================================

declare global {
  namespace globalThis {
    interface Request {
      requestId?: string;
    }
  }
}

// ============================================================================
// Request ID Generation
// ============================================================================

/**
 * Generate a compact request ID.
 * Format: 8 hex chars (good for ~4 billion values, sufficient for request IDs).
 */
function generateRequestId(): string {
  return randomBytes(4).toString('hex');
}

// ============================================================================
// Middleware
// ============================================================================

/**
 * Add a request ID to the request and return it.
 * The ID is attached as `request.id` for use in logging and response headers.
 */
export function assignRequestId(req: Request): string {
  const id = generateRequestId();
  (req as any).requestId = id;
  return id;
}

/**
 * Get the request ID from a request (or generate one if missing).
 */
export function getRequestId(req: Request): string {
  return (req as any).requestId ?? assignRequestId(req);
}
