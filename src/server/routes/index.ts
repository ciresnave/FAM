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
import { adminSessionRoutes } from './adminSession';
import { adminUiRoutes } from './adminUi';
import { taskRoutes } from './tasks';
import { rulingRoutes } from './rulings';
import { voucherRoutes } from './vouchers';
import { PermissionChecker } from '../services/permissionChecker';

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
  // Register all route groups
  const allRoutes: Route[] = [
    ...accountRoutes(ctx),
    ...entityRoutes(ctx, wsManager),
    ...channelRoutes(ctx, wsManager),
    ...messageRoutes(ctx, sendService),
    ...healthRoutes(ctx),
    ...adminRoutes(ctx, wsManager),
    ...adminSessionRoutes(ctx),
    ...adminUiRoutes(),
    ...taskRoutes(ctx, new PermissionChecker(ctx)),
    ...rulingRoutes(ctx),
    ...voucherRoutes(ctx),
  ];
  
  return buildRouteMap(allRoutes);
}

/**
 * Build the pattern -> handler map.
 */
export function buildRouteMap(
  allRoutes: Route[]
): Map<string, { method: string; handler: RouteHandler }> {
  const routes = new Map<string, { method: string; handler: RouteHandler }>();

  for (const route of allRoutes) {
    // Refuse duplicates rather than overwriting. The map is keyed by PATTERN
    // alone, so a second route on the same path used to replace the first with
    // no diagnostic — including across method, which meant a GET and a POST on
    // one path could not coexist and the loser vanished quietly.
    //
    // That failure is worse than an ordinary bug because it is invisible to the
    // safety net: integration.test.ts enumerates the routes that REGISTERED and
    // requires each to be classified, so a route lost here is not merely
    // untested, it is unenumerable. Fail at startup instead.
    const existing = routes.get(route.pattern);
    if (existing) {
      throw new Error(
        `Duplicate route pattern '${route.pattern}' ` +
          `(${existing.method} already registered, then ${route.method}). ` +
          'Patterns must be unique: the route map is keyed by pattern, not by ' +
          'method, so one of these would be silently discarded.'
      );
    }

    routes.set(route.pattern, {
      method: route.method,
      handler: route.handler,
    });
  }

  return routes;
}

