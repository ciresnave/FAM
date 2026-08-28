// Message Routes for FAM Server

import type { DatabaseContext } from '../../db/transaction';
import type { Route } from './index';
import type { MessageSendService } from '../services/messageSend';
import {
  NotFoundError,
  ForbiddenError,
} from '../../types/errors';
import {
  validateEntityId,
  validateChannelId,
  validatePagination,
} from '../../types/validation';
import { entityRateLimiter, RateLimitError } from '../middleware/rateLimit';
import { requireEntitySession } from '../middleware/auth';

// ============================================================================
// Message Routes
// ============================================================================

export function messageRoutes(
  ctx: DatabaseContext,
  sendService: MessageSendService
): Route[] {
  return [
    // POST /messages/send
    // Send a message (DM or channel) — delegates to the shared send service
    {
      method: 'POST',
      pattern: '/messages/send',
      handler: async (req) => {
        // Identity comes from the authenticated session, not the body.
        const { entityId: entity_id, body } = await requireEntitySession(ctx, req);
        const { channel_id, to_entity, text } = body;

        if (!text) {
          return new Response(
            JSON.stringify({ error: 'Missing text' }),
            { status: 400, headers: { 'Content-Type': 'application/json' } }
          );
        }
        
        // Rate limit by entity
        try {
          entityRateLimiter.check(entity_id);
        } catch (e) {
          if (e instanceof RateLimitError) {
            return new Response(
              JSON.stringify(e.toJSON()),
              { status: 429, headers: { 'Content-Type': 'application/json', 'Retry-After': String(e.retryAfter) } }
            );
          }
          throw e;
        }
        
        if (!channel_id && !to_entity) {
          return new Response(
            JSON.stringify({ error: 'Must specify either channel_id or to_entity' }),
            { status: 400, headers: { 'Content-Type': 'application/json' } }
          );
        }
        
        // All validation, authorization, persistence, and push live in the service.
        // Errors (FamError subclasses) bubble to the HTTP error handler.
        const { message, delivery } = channel_id
          ? await sendService.sendChannelMessage(entity_id, channel_id, text)
          : await sendService.sendDirectMessage(entity_id, to_entity, text);

        // The delivery block is the point: 201 alone said "stored" and was read
        // as "delivered". Any outcome that is not delivery must be legible.
        return new Response(
          JSON.stringify({ message_id: message.id, delivery }),
          { status: 201, headers: { 'Content-Type': 'application/json' } }
        );
      },
    },
    
    // POST /messages/delivered
    // Mark messages as delivered
    {
      method: 'POST',
      pattern: '/messages/delivered',
      handler: async (req) => {
        const { entityId: entity_id, body } = await requireEntitySession(ctx, req);
        const { message_ids } = body;

        if (!message_ids) {
          return new Response(
            JSON.stringify({ error: 'Missing message_ids' }),
            { status: 400, headers: { 'Content-Type': 'application/json' } }
          );
        }
        
        // Rate limit by entity
        try {
          entityRateLimiter.check(entity_id);
        } catch (e) {
          if (e instanceof RateLimitError) {
            return new Response(
              JSON.stringify(e.toJSON()),
              { status: 429, headers: { 'Content-Type': 'application/json', 'Retry-After': String(e.retryAfter) } }
            );
          }
          throw e;
        }
        
        validateEntityId(entity_id);
        
        if (!Array.isArray(message_ids) || message_ids.length === 0) {
          return new Response(
            JSON.stringify({ error: 'message_ids must be a non-empty array' }),
            { status: 400, headers: { 'Content-Type': 'application/json' } }
          );
        }

        // Verify entity exists
        const entity = ctx.entities.getById(entity_id);
        if (!entity) {
          throw new NotFoundError('Entity', entity_id);
        }

        // Batch ownership validation: each message must be addressed to this
        // entity (DM) or to a channel the entity belongs to (single query)
        const validMessageIds = ctx.messages.getOwnedMessageIds(entity_id, message_ids);

        if (validMessageIds.length === 0) {
          return new Response(
            JSON.stringify({ error: 'No valid messages found to mark as delivered' }),
            { status: 404, headers: { 'Content-Type': 'application/json' } }
          );
        }
        
        // Acknowledgement is per recipient — this entity's delivery rows only.
        ctx.messages.markDelivered(entity_id, validMessageIds);
        
        return new Response(
          JSON.stringify({ ok: true, marked: validMessageIds.length }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      },
    },
    
    // POST /messages/history
    // Get message history
    {
      method: 'POST',
      pattern: '/messages/history',
      handler: async (req) => {
        const { entityId: entity_id, body } = await requireEntitySession(ctx, req);
        const { channel_id, other_entity_id, limit, offset } = body;

        // Rate limit by entity
        try {
          entityRateLimiter.check(entity_id);
        } catch (e) {
          if (e instanceof RateLimitError) {
            return new Response(
              JSON.stringify(e.toJSON()),
              { status: 429, headers: { 'Content-Type': 'application/json', 'Retry-After': String(e.retryAfter) } }
            );
          }
          throw e;
        }
        
        validateEntityId(entity_id);
        
        // Verify entity exists
        const entity = ctx.entities.getById(entity_id);
        if (!entity) {
          throw new NotFoundError('Entity', entity_id);
        }
        
        // Validate pagination params
        const pagination = validatePagination({ limit, offset });
        
        let messages;
        
        if (channel_id) {
          validateChannelId(channel_id);
          
          // Verify channel exists
          const channel = ctx.channels.getById(channel_id);
          if (!channel) {
            throw new NotFoundError('Channel', channel_id);
          }
          
          // Verify entity is a member of the channel
          if (!ctx.channels.isMember(channel_id, entity_id)) {
            throw new ForbiddenError('You are not a member of this channel');
          }
          
          let channelMessages = await ctx.messages.getChannelHistory(channel_id, pagination.limit + pagination.offset);
          // Apply offset after fetch (since DB queries don't support offset natively in repo)
          messages = channelMessages.slice(pagination.offset, pagination.offset + pagination.limit);
        } else if (other_entity_id) {
          validateEntityId(other_entity_id);
          
          // Verify other entity exists
          const otherEntity = ctx.entities.getById(other_entity_id);
          if (!otherEntity) {
            throw new NotFoundError('Entity', other_entity_id);
          }
          
          let dmMessages = await ctx.messages.getDirectMessageHistory(
            entity_id,
            other_entity_id,
            pagination.limit + pagination.offset
          );
          messages = dmMessages.slice(pagination.offset, pagination.offset + pagination.limit);
        } else {
          return new Response(
            JSON.stringify({ error: 'Must specify either channel_id or other_entity_id' }),
            { status: 400, headers: { 'Content-Type': 'application/json' } }
          );
        }
        
        return new Response(
          JSON.stringify({ messages, limit: pagination.limit, offset: pagination.offset }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      },
    },
  ];
}

