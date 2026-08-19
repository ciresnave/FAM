// Health Routes for FAM Server

import type { DatabaseContext } from '../../db/transaction';
import type { Route } from './index';

// ============================================================================
// Health Routes
// ============================================================================

export function healthRoutes(ctx: DatabaseContext): Route[] {
  return [
    // GET /health
    // Server health check
    {
      method: 'GET',
      pattern: '/health',
      handler: async () => {
        // Count entities
        const entityCount = ctx.db.prepare('SELECT COUNT(*) as count FROM entities').get() as { count: number };
        
        // Count channels
        const channelCount = ctx.db.prepare('SELECT COUNT(*) as count FROM channels').get() as { count: number };
        
        // Count messages
        const messageCount = ctx.db.prepare('SELECT COUNT(*) as count FROM messages').get() as { count: number };
        
        // Count active sessions
        const sessionCount = ctx.sessions.getActiveCount();
        
        return new Response(
          JSON.stringify({
            status: 'ok',
            entities: entityCount.count,
            channels: channelCount.count,
            messages: messageCount.count,
            sessions: sessionCount,
            uptime: process.uptime(),
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      },
    },
    
    // GET /
    // Root endpoint
    {
      method: 'GET',
      pattern: '/',
      handler: async () => {
        return new Response(
          JSON.stringify({
            name: 'Federated Agent Messaging (FAM)',
            version: '0.1.0',
            status: 'running',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      },
    },
  ];
}

