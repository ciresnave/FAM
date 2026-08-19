// Entity Routes for FAM Server

import type { DatabaseContext } from '../../db/transaction';
import type { WebSocketManager } from '../websocket';
import type { Route } from './index';
import {
  NotFoundError,
  UnauthorizedError,
  ChallengeExpiredError,
  SignatureInvalidError,
} from '../../types/errors';
import { validateEntityId, validatePagination } from '../../types/validation';
import {
  generateChallenge,
  storeChallenge,
  consumeChallenge,
  verifyChallengeResponse,
} from '../../crypto/challenge';

// ============================================================================
// Entity Routes
// ============================================================================

export function entityRoutes(
  ctx: DatabaseContext,
  wsManager: WebSocketManager
): Route[] {
  return [
    // POST /entities/connect
    // Initiate connection - returns challenge nonce
    {
      method: 'POST',
      pattern: '/entities/connect',
      handler: async (req) => {
        const body = await req.json() as any;
        const { entity_id, public_key } = body;
        
        if (!entity_id || !public_key) {
          return new Response(
            JSON.stringify({ error: 'Missing entity_id or public_key' }),
            { status: 400, headers: { 'Content-Type': 'application/json' } }
          );
        }
        
        validateEntityId(entity_id);
        
        // Verify entity exists
        const entity = ctx.entities.getById(entity_id);
        if (!entity) {
          throw new NotFoundError('Entity', entity_id);
        }
        
        // Verify public key matches
        if (entity.public_key !== public_key) {
          throw new UnauthorizedError('Public key does not match');
        }
        
        // Generate and store challenge
        const { nonce } = generateChallenge();
        storeChallenge(ctx.db, entity_id, nonce);
        
        return new Response(
          JSON.stringify({ nonce }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      },
    },
    
    // POST /entities/authenticate
    // Complete authentication - verify signature and create session
    {
      method: 'POST',
      pattern: '/entities/authenticate',
      handler: async (req) => {
        const body = await req.json() as any;
        const { entity_id, nonce, signature } = body;
        
        if (!entity_id || !nonce || !signature) {
          return new Response(
            JSON.stringify({ error: 'Missing entity_id, nonce, or signature' }),
            { status: 400, headers: { 'Content-Type': 'application/json' } }
          );
        }
        
        validateEntityId(entity_id);
        
        // Get and consume challenge
        const challenge = consumeChallenge(ctx.db, entity_id);
        if (!challenge) {
          throw new ChallengeExpiredError();
        }
        
        // Get entity
        const entity = ctx.entities.getById(entity_id);
        if (!entity) {
          throw new NotFoundError('Entity', entity_id);
        }
        
        // Verify challenge response
        const valid = await verifyChallengeResponse(
          challenge,
          { nonce, signature },
          entity.public_key
        );
        
        if (!valid) {
          throw new SignatureInvalidError();
        }
        
        // Create session
        const session = ctx.sessions.create(entity_id);
        
        // Update entity status
        ctx.entities.updateStatus(entity_id, 'online');
        
        // Fetch undelivered messages for this entity.
        // NOTE: We do NOT mark them delivered here — the client must acknowledge
        // via /messages/delivered after processing. This gives at-least-once
        // delivery semantics (client may see duplicates if it crashes mid-processing).
        const undelivered = await ctx.messages.getUndelivered(entity_id, 50);
        
        // Build WebSocket URL from server config
        const host = process.env.FAM_HOST || '127.0.0.1';
        const port = process.env.FAM_PORT || '7899';
        const wsUrl = `ws://${host}:${port}/ws?entity_id=${encodeURIComponent(entity_id)}&session_id=${session.id}`;
        
        return new Response(
          JSON.stringify({
            session_id: session.id,
            websocket_url: wsUrl,
            undelivered_messages: undelivered,
            availability: entity.availability,
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      },
    },
    
    // POST /entities/disconnect
    // End session
    {
      method: 'POST',
      pattern: '/entities/disconnect',
      handler: async (req) => {
        const body = await req.json() as any;
        const { entity_id, session_id } = body;
        
        if (!entity_id || !session_id) {
          return new Response(
            JSON.stringify({ error: 'Missing entity_id or session_id' }),
            { status: 400, headers: { 'Content-Type': 'application/json' } }
          );
        }
        
        // Verify session exists
        const session = ctx.sessions.getById(session_id);
        if (!session || session.entity_id !== entity_id) {
          throw new NotFoundError('Session', session_id);
        }
        
        // Check for remaining sessions BEFORE deletion to avoid race condition
        const sessionCount = ctx.sessions.getCountByEntityId(entity_id);
        
        // Delete session
        ctx.sessions.delete(session_id);
        
        // Update entity status if this was the last session
        if (sessionCount <= 1) {
          ctx.entities.updateStatus(entity_id, 'offline');
        }
        
        return new Response(
          JSON.stringify({ ok: true }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      },
    },
    
    // POST /entities/heartbeat
    // Update session heartbeat
    {
      method: 'POST',
      pattern: '/entities/heartbeat',
      handler: async (req) => {
        const body = await req.json() as any;
        const { entity_id, session_id } = body;
        
        if (!entity_id || !session_id) {
          return new Response(
            JSON.stringify({ error: 'Missing entity_id or session_id' }),
            { status: 400, headers: { 'Content-Type': 'application/json' } }
          );
        }
        
        const session = ctx.sessions.getById(session_id);
        if (!session || session.entity_id !== entity_id) {
          throw new NotFoundError('Session', session_id);
        }
        
        ctx.sessions.updateHeartbeat(session_id);
        
        return new Response(
          JSON.stringify({ ok: true }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      },
    },
    
    // POST /entities/availability
    // Set availability (user intent: available/unavailable).
    // Requires a valid session — availability gates message delivery, so it
    // must be set by the entity itself, not by arbitrary callers.
    {
      method: 'POST',
      pattern: '/entities/availability',
      handler: async (req) => {
        const body = await req.json() as any;
        const { entity_id, session_id, availability } = body;
        
        if (!entity_id || !session_id || !availability) {
          return new Response(
            JSON.stringify({ error: 'Missing entity_id, session_id, or availability' }),
            { status: 400, headers: { 'Content-Type': 'application/json' } }
          );
        }
        
        if (!['available', 'unavailable'].includes(availability)) {
          return new Response(
            JSON.stringify({ error: 'Invalid availability. Must be: available, unavailable' }),
            { status: 400, headers: { 'Content-Type': 'application/json' } }
          );
        }
        
        validateEntityId(entity_id);
        
        // Session must exist, belong to this entity, and be fresh
        const session = ctx.sessions.getById(session_id);
        if (!session || session.entity_id !== entity_id) {
          throw new NotFoundError('Session', session_id);
        }
        const lastHeartbeat = new Date(session.last_heartbeat).getTime();
        if (Date.now() - lastHeartbeat > 60 * 1000) {
          throw new UnauthorizedError('Session expired');
        }
        
        // Flip availability: broadcast + flush queued backlog on available
        const flushed = await wsManager.setAvailability(entity_id, availability);
        
        return new Response(
          JSON.stringify({ ok: true, availability, messages_pushed: flushed }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      },
    },
    
    // POST /entities/status
    // Update entity status
    {
      method: 'POST',
      pattern: '/entities/status',
      handler: async (req) => {
        const body = await req.json() as any;
        const { entity_id, status } = body;
        
        if (!entity_id || !status) {
          return new Response(
            JSON.stringify({ error: 'Missing entity_id or status' }),
            { status: 400, headers: { 'Content-Type': 'application/json' } }
          );
        }
        
        if (!['online', 'offline', 'away'].includes(status)) {
          return new Response(
            JSON.stringify({ error: 'Invalid status. Must be: online, offline, away' }),
            { status: 400, headers: { 'Content-Type': 'application/json' } }
          );
        }
        
        ctx.entities.updateStatus(entity_id, status);
        
        return new Response(
          JSON.stringify({ ok: true }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      },
    },
    
    // POST /entities/list
    // List entities with filters.
    // scope: 'directory' = own account's entities + entities actively granted
    // to the caller's account (cross-account visibility is default-deny);
    // 'channel' = members of a channel; 'online' = connected entities;
    // default 'all' = every entity on the server.
    {
      method: 'POST',
      pattern: '/entities/list',
      handler: async (req) => {
        const body = await req.json() as any;
        const { entity_id, scope, channel_id, limit, offset } = body;
        
        // Validate pagination params
        const pagination = validatePagination({ limit, offset });
        
        let entities;
        
        if (scope === 'directory') {
          // Directory scope is caller-relative: resolve the caller's account
          if (!entity_id) {
            return new Response(
              JSON.stringify({ error: 'entity_id is required for scope "directory"' }),
              { status: 400, headers: { 'Content-Type': 'application/json' } }
            );
          }
          
          validateEntityId(entity_id);
          
          const caller = ctx.entities.getById(entity_id);
          if (!caller) {
            throw new NotFoundError('Entity', entity_id);
          }
          
          entities = ctx.entities.getDirectoryForAccount(caller.account_id);
        } else if (scope === 'channel' && channel_id) {
          entities = ctx.entities.getByChannelId(channel_id);
        } else if (scope === 'online') {
          entities = ctx.entities.getOnline();
        } else {
          // Default: all entities (via repo so capabilities parse and
          // availability is included)
          entities = ctx.entities.getAll();
        }
        
        // Apply pagination
        const total = entities.length;
        const paginatedEntities = entities.slice(pagination.offset, pagination.offset + pagination.limit);
        
        return new Response(
          JSON.stringify({ entities: paginatedEntities, total, limit: pagination.limit, offset: pagination.offset }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      },
    },
  ];
}

