// FAM HTTP Server Setup
//
// Main HTTP server with routing for all FAM endpoints.

import { getDatabaseContext, closeDatabase } from '../db';
import { setupRoutes } from './routes';
import { WebSocketManager } from './websocket';
import { MessageSendService } from './services/messageSend';
import { PermissionChecker } from './services/permissionChecker';
import { cleanupStaleSessions, cleanupExpiredOAuthStates, cleanupExpiredInvitations, cleanupExpiredChallenges } from '../db/schema';
import { ipRateLimiter, entityRateLimiter, getClientIp, RateLimitError } from './middleware/rateLimit';
import { assignRequestId, getRequestId } from './middleware/requestId';
import { RequestEntityTooLargeError, ValidationError } from '../types/errors';
import { logger } from '../utils/logger';
import { DEFAULT_PORT } from '../config';

// ============================================================================
// Configuration
// ============================================================================

const SERVER_SECRET = process.env.FAM_SERVER_SECRET;
if (!SERVER_SECRET) {
  logger.error('FAM_SERVER_SECRET environment variable is required');
  process.exit(1);
}

const ALLOWED_ORIGINS = process.env.FAM_ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'];
const MAX_BODY_SIZE = parseInt(process.env.FAM_MAX_BODY_SIZE || '1048576', 10); // 1MB default
const MESSAGE_RETENTION_DAYS = parseInt(process.env.FAM_MESSAGE_RETENTION_DAYS || '30', 10); // 30 days default

// Validate OAuth provider configuration (warn if none configured)
const hasGoogleOAuth = !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET);
const hasGitHubOAuth = !!(process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET);
if (!hasGoogleOAuth && !hasGitHubOAuth) {
  logger.warn('No OAuth providers configured (GOOGLE_CLIENT_ID/SECRET or GITHUB_CLIENT_ID/SECRET). Account creation will not work.');
}

// Validate host/port
const PORT = parseInt(process.env.FAM_PORT || String(DEFAULT_PORT), 10);
if (isNaN(PORT) || PORT < 1 || PORT > 65535) {
  logger.error('FAM_PORT must be a valid port number (1-65535)');
  process.exit(1);
}

const HOST = process.env.FAM_HOST || '127.0.0.1';
if (!HOST.match(/^[\d.]+$/) && !HOST.match(/^[a-zA-Z0-9.-]+$/)) {
  logger.error('FAM_HOST must be a valid hostname or IP address');
  process.exit(1);
}

// ============================================================================
// Types
// ============================================================================

export interface ServerConfig {
  port: number;
  host: string;
}

// ============================================================================
// Server State
// ============================================================================

let server: ReturnType<typeof Bun.serve> | null = null;
let wsManager: WebSocketManager | null = null;

// ============================================================================
// Server Lifecycle
// ============================================================================

/**
 * Start the FAM HTTP server.
 */
export function startServer(config: ServerConfig): void {
  const ctx = getDatabaseContext();
  wsManager = new WebSocketManager(ctx);
  
  // Encryption-mode consistency warning: enabling encryption does not
  // retroactively encrypt existing plaintext rows, and reads only decrypt
  // when the flag is on — mixed data must be avoided.
  if (process.env.FAM_ENCRYPT_MESSAGES === 'true' && ctx.messages.getCount() > 0) {
    logger.warn(
      'FAM_ENCRYPT_MESSAGES=true with existing messages: rows written before enabling ' +
      'encryption remain in plaintext. Reads only decrypt when the flag is on — ' +
      'pick one setting and keep it (a re-encryption migration is planned for Phase 5).'
    );
  }
  
  // Shared send service — single enforcement point for message sending.
  // Bound to both the routes and the WebSocket manager.
  const sendService = new MessageSendService(ctx, wsManager, new PermissionChecker(ctx));
  wsManager.setSendService(sendService);
  
  const routes = setupRoutes(ctx, wsManager, sendService);
  
  server = Bun.serve({
    port: config.port,
    hostname: config.host,
    
    fetch(req, server) {
      // Handle WebSocket upgrade
      const url = new URL(req.url);
      
      if (url.pathname === '/ws') {
        const entityId = url.searchParams.get('entity_id');
        const sessionId = url.searchParams.get('session_id');
        
        if (!entityId || !sessionId) {
          return new Response('Missing entity_id or session_id', { status: 400 });
        }
        
        // Validate session exists and belongs to this entity
        // (uses the shared server context — single source of truth)
        const session = ctx.sessions.getById(sessionId);
        if (!session || session.entity_id !== entityId) {
          return new Response('Invalid session', { status: 401 });
        }
        
        // Check session is still active (heartbeat within last 60 seconds)
        const lastHeartbeat = new Date(session.last_heartbeat).getTime();
        if (Date.now() - lastHeartbeat > 60 * 1000) {
          return new Response('Session expired', { status: 401 });
        }
        
        const upgraded = server.upgrade(req, {
          data: { entityId, sessionId },
        });
        
        if (upgraded) {
          return undefined; // WebSocket handled
        }
        return new Response('WebSocket upgrade failed', { status: 500 });
      }
      
      // Handle HTTP requests
      return handleRequest(req, routes);
    },
    
    websocket: {
      open(ws) {
        const data = ws.data as { entityId: string; sessionId: string };
        wsManager!.handleConnection(ws, data.entityId, data.sessionId);
      },
      
      message(ws, message) {
        wsManager!.handleMessage(ws, message.toString());
      },
      
      close(ws) {
        wsManager!.handleClose(ws);
      },
      
      drain(ws) {
        // Handle backpressure
      },
    },
  });
  
  logger.info('FAM server running', { port: config.port, host: config.host });
  
  // Start periodic cleanup
  startCleanupInterval();
}

/**
 * Stop the FAM server.
 */
export function stopServer(): void {
  if (server) {
    server.stop();
    server = null;
  }
  
  if (wsManager) {
    wsManager.shutdown();
    wsManager = null;
  }
  
  closeDatabase();
  logger.info('FAM server stopped');
}

// ============================================================================
// Request Handling
// ============================================================================

type RouteHandler = (
  req: Request,
  params: Record<string, string>
) => Promise<Response>;

type RouteMap = Map<string, { method: string; handler: RouteHandler }>;

async function handleRequest(
  req: Request,
  routes: RouteMap
): Promise<Response> {
  const url = new URL(req.url);
  const method = req.method;
  
  // Assign request ID
  const requestId = assignRequestId(req);
  
  // CORS headers
  const origin = req.headers.get('Origin');
  const corsHeaders: Record<string, string> = {
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'X-Request-ID': requestId,
  };
  
  // Check if origin is allowed
  if (ALLOWED_ORIGINS.includes('*')) {
    corsHeaders['Access-Control-Allow-Origin'] = origin || '*';
  } else if (origin && ALLOWED_ORIGINS.includes(origin)) {
    corsHeaders['Access-Control-Allow-Origin'] = origin;
  }
  
  // Handle preflight
  if (method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }
  
  // Rate limiting by IP
  const clientIp = getClientIp(req);
  try {
    ipRateLimiter.check(clientIp);
  } catch (e) {
    if (e instanceof RateLimitError) {
      return new Response(
        JSON.stringify(e.toJSON()),
        {
          status: 429,
          headers: {
            ...corsHeaders,
            'Content-Type': 'application/json',
            'Retry-After': String(e.retryAfter),
          },
        }
      );
    }
    throw e;
  }
  
  // Find matching route
  let pathMatched = false;
  for (const [pattern, route] of routes) {
    const match = matchRoute(pattern, url.pathname);
    if (match) {
      if (route.method === method) {
        try {
          const response = await route.handler(req, match);
          
          // Add rate limit headers
          const rateLimitInfo = ipRateLimiter.getInfo(clientIp);
          response.headers.set('X-RateLimit-Limit', '1000');
          response.headers.set('X-RateLimit-Remaining', String(rateLimitInfo.remaining));
          
          return response;
        } catch (e) {
          return handleError(e, corsHeaders);
        }
      }
      pathMatched = true;
    }
  }
  
  if (pathMatched) {
    // Path exists but method is wrong
    return new Response(
      JSON.stringify({ error: 'Method not allowed', code: 'METHOD_NOT_ALLOWED' }),
      { status: 405, headers: { ...corsHeaders, 'Content-Type': 'application/json', 'Allow': 'GET, POST, OPTIONS' } }
    );
  }
  
  // 404 for unknown routes
  return new Response(
    JSON.stringify({ error: 'Not found', code: 'NOT_FOUND' }),
    { status: 404, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
  );
}

function matchRoute(pattern: string, pathname: string): Record<string, string> | null {
  // Simple route matching: /accounts/:id matches /accounts/123
  const patternParts = pattern.split('/');
  const pathnameParts = pathname.split('/');
  
  if (patternParts.length !== pathnameParts.length) {
    return null;
  }
  
  const params: Record<string, string> = {};
  
  for (let i = 0; i < patternParts.length; i++) {
    if (patternParts[i]?.startsWith(':')) {
      const paramName = patternParts[i]?.slice(1);
      const paramValue = pathnameParts[i];
      if (paramName && paramValue) {
        params[paramName] = paramValue;
      }
    } else if (patternParts[i] !== pathnameParts[i]) {
      return null;
    }
  }
  
  return params;
}

function handleError(e: unknown, corsHeaders: Record<string, string>): Response {
  if (e && typeof e === 'object' && 'statusCode' in e) {
    const err = e as { statusCode: number; toJSON: () => object };
    return new Response(
      JSON.stringify(err.toJSON()),
      { status: err.statusCode, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
  
  logger.error('Unhandled error', { error: e });
  return new Response(
    JSON.stringify({ error: 'Internal server error', code: 'INTERNAL_ERROR' }),
    { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
  );
}

/**
 * Safely parse JSON from request body with size limit.
 */
export async function parseJsonBody(req: Request): Promise<unknown> {
  // Check Content-Length header
  const contentLength = req.headers.get('Content-Length');
  if (contentLength && parseInt(contentLength, 10) > MAX_BODY_SIZE) {
    throw new RequestEntityTooLargeError(MAX_BODY_SIZE);
  }
  
  try {
    const body = await req.json();
    return body;
  } catch (e) {
    if (e instanceof SyntaxError) {
      throw new ValidationError('Invalid JSON in request body');
    }
    throw e;
  }
}

// ============================================================================
// Cleanup
// ============================================================================

let cleanupInterval: ReturnType<typeof setInterval> | null = null;

function startCleanupInterval(): void {
  cleanupInterval = setInterval(() => {
    const ctx = getDatabaseContext();
    cleanupExpiredChallenges(ctx.db);
    cleanupStaleSessions(ctx.db);
    cleanupExpiredOAuthStates(ctx.db);
    cleanupExpiredInvitations(ctx.db);

    // Mark expired grants as revoked
    const expiredGrants = ctx.grants.revokeExpired();
    if (expiredGrants > 0) {
      logger.info('Expired grants revoked', { count: expiredGrants });
    }

    // Automated message retention cleanup
    if (MESSAGE_RETENTION_DAYS > 0) {
      const deletedCount = ctx.messages.deleteOlderThan(MESSAGE_RETENTION_DAYS);
      if (deletedCount > 0) {
        logger.info('Message retention cleanup', { deleted: deletedCount, retentionDays: MESSAGE_RETENTION_DAYS });
      }
    }
  }, 5 * 60 * 1000); // Every 5 minutes
}

// ============================================================================
// Main Entry Point
// ============================================================================

// Start server if run directly
if (import.meta.main) {
  startServer({ port: PORT, host: HOST });
  
  // Handle graceful shutdown
  process.on('SIGINT', () => {
    logger.info('Received SIGINT, shutting down...');
    stopServer();
    process.exit(0);
  });
  
  process.on('SIGTERM', () => {
    logger.info('Received SIGTERM, shutting down...');
    stopServer();
    process.exit(0);
  });
}
