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
          : await sendService.sendDirectMessage(entity_id, to_entity, text, body.refs);

        // The delivery block is the point: 201 alone said "stored" and was read
        // as "delivered". Any outcome that is not delivery must be legible.
        return new Response(
          JSON.stringify({ message_id: message.id, delivery }),
          { status: 201, headers: { 'Content-Type': 'application/json' } }
        );
      },
    },
    
    // POST /messages/send-sealed
    // Send a direct message the server cannot read.
    //
    // ⚠️ A SEPARATE ROUTE, NOT A FLAG ON /messages/send. The service already
    // splits sealed from plaintext into two methods so a caller must NAME the
    // path; folding them back together at the edge would undo that one layer
    // up. "Sealed if an envelope is present, plaintext otherwise" is a
    // disjunction, and the failure it permits is the one this whole increment
    // exists to prevent — a client that meant to seal, didn't, and got a 201.
    //
    // The route holds NO opinion about envelope validity. Shape, the
    // sender/recipient binding and the signature are all the service's, for the
    // same reason the permission matrix is: two places that check the same
    // thing are two answers waiting to drift.
    {
      method: 'POST',
      pattern: '/messages/send-sealed',
      handler: async (req) => {
        const { entityId: entity_id, body } = await requireEntitySession(ctx, req);
        const { to_entity, envelope, text } = body;

        // Both fields present is an AMBIGUITY, and resolving it silently is how
        // the wrong path gets chosen. Whichever the server picked, half of
        // callers would be surprised — and the surprising half sends plaintext
        // believing it sealed.
        if (text !== undefined && envelope !== undefined) {
          return new Response(
            JSON.stringify({
              error:
                'Send both "text" and "envelope"? Refusing: they name different send paths. ' +
                'Use /messages/send for text, /messages/send-sealed for an envelope.',
            }),
            { status: 400, headers: { 'Content-Type': 'application/json' } }
          );
        }

        // Masked by the service's shape check on status alone — both give 400.
        // Kept for the MESSAGE: a caller who simply forgot the field gets
        // "Missing envelope" rather than a list of eleven fields that are all
        // missing because the object is not there. Asserted in the tests, or
        // this guard would be invisible and get deleted as redundant.
        if (!envelope) {
          return new Response(
            JSON.stringify({ error: 'Missing envelope' }),
            { status: 400, headers: { 'Content-Type': 'application/json' } }
          );
        }

        if (!to_entity) {
          return new Response(
            // Channels are not supported yet: a channel message needs one
            // content key wrapped per recipient, which is not built. Saying so
            // beats a generic rejection that reads like a malformed request.
            JSON.stringify({ error: 'Must specify to_entity. Sealed channel messages are not supported yet.' }),
            { status: 400, headers: { 'Content-Type': 'application/json' } }
          );
        }

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

        const { message, delivery } = await sendService.sendSealedDirectMessage(
          entity_id,
          to_entity,
          envelope
        );

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

