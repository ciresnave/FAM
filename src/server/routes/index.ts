// Route Setup for FAM Server

import type { DatabaseContext } from '../../db/transaction';
import type { WebSocketManager } from '../websocket';
import type { MessageSendService } from '../services/messageSend';
import { accountRoutes } from './accounts';
import { entityRoutes } from './entities';
import { channelRoutes } from './channels';
import { messageRoutes } from './messages';
import { healthRoutes } from './health';
import { adminRoutes } from './admin';

// ============================================================================
// Types
// ============================================================================

export type RouteHandler = (
  req: Request,
  params: Record<string, string>
) => Promise<Response>;

export interface Route {
  method: string;
  pattern: string;
  handler: RouteHandler;
}

// ============================================================================
// Route Registration
// ============================================================================

export function setupRoutes(
  ctx: DatabaseContext,
  wsManager: WebSocketManager,
  sendService: MessageSendService
): Map<string, { method: string; handler: RouteHandler }> {
  const routes = new Map<string, { method: string; handler: RouteHandler }>();
  
  // Register all route groups
  const allRoutes: Route[] = [
    ...accountRoutes(ctx),
    ...entityRoutes(ctx, wsManager),
    ...channelRoutes(ctx, wsManager),
    ...messageRoutes(ctx, sendService),
    ...healthRoutes(ctx),
    ...adminRoutes(ctx),
  ];
  
  // Convert to map for O(1) lookup
  for (const route of allRoutes) {
    routes.set(route.pattern, {
      method: route.method,
      handler: route.handler,
    });
  }
  
  return routes;
}

