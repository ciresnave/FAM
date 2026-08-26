// Channel Routes for FAM Server

import type { DatabaseContext } from '../../db/transaction';
import type { WebSocketManager } from '../websocket';
import type { Route } from './index';
import {
  NotFoundError,
  ForbiddenError,
  EntityNotInChannelError,
  InsufficientCapabilitiesError,
} from '../../types/errors';
import {
  validateEntityId,
  validateChannelId,
  validateChannelName,
  validatePagination,
} from '../../types/validation';
import { entityRateLimiter, RateLimitError } from '../middleware/rateLimit';
import { requireEntitySession } from '../middleware/auth';

// ============================================================================
// Channel Routes
// ============================================================================

export function channelRoutes(ctx: DatabaseContext, wsManager?: WebSocketManager): Route[] {
  return [
    // POST /channels/create
    // Create a new channel
    {
      method: 'POST',
      pattern: '/channels/create',
      handler: async (req) => {
        const { entityId: entity_id, body } = await requireEntitySession(ctx, req);
        const { name, is_public } = body;
        
        if (!entity_id || !name) {
          return new Response(
            JSON.stringify({ error: 'Missing entity_id or name' }),
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
        validateChannelName(name);
        
        // Verify entity exists
        const entity = ctx.entities.getById(entity_id);
        if (!entity) {
          throw new NotFoundError('Entity', entity_id);
        }
        
        // Check capabilities
        if (!entity.capabilities.can_create_channels) {
          throw new InsufficientCapabilitiesError('can_create_channels');
        }
        
        // Create channel
        const channel = ctx.channels.create(name, entity_id, is_public ?? false);
        
        return new Response(
          JSON.stringify({ channel }),
          { status: 201, headers: { 'Content-Type': 'application/json' } }
        );
      },
    },
    
    // POST /channels/join
    // Join a channel
    {
      method: 'POST',
      pattern: '/channels/join',
      handler: async (req) => {
        const { entityId: entity_id, body } = await requireEntitySession(ctx, req);
        const { channel_id } = body;
        
        if (!entity_id || !channel_id) {
          return new Response(
            JSON.stringify({ error: 'Missing entity_id or channel_id' }),
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
        validateChannelId(channel_id);
        
        // Verify entity exists
        const entity = ctx.entities.getById(entity_id);
        if (!entity) {
          throw new NotFoundError('Entity', entity_id);
        }
        
        // Check capabilities
        if (!entity.capabilities.can_join_channel) {
          throw new InsufficientCapabilitiesError('can_join_channel');
        }
        
        // Verify channel exists
        const channel = ctx.channels.getById(channel_id);
        if (!channel) {
          throw new NotFoundError('Channel', channel_id);
        }

        // Check if channel is private and entity is not invited
        if (!channel.is_public) {
          const hasInvitation = ctx.invitations.hasPending(channel_id, entity_id);
          if (!hasInvitation) {
            throw new ForbiddenError('Cannot join private channel without invitation');
          }
          // Accept the invitation
          const pendingInvites = ctx.invitations.getPendingForEntity(entity_id);
          const invite = pendingInvites.find(i => i.channel_id === channel_id);
          if (invite) {
            ctx.invitations.accept(invite.id);
          }
        }
        
        // Add member
        const member = ctx.channels.addMember(channel_id, entity_id, 'member');
        
        return new Response(
          JSON.stringify({ member }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      },
    },
    
    // POST /channels/leave
    // Leave a channel
    {
      method: 'POST',
      pattern: '/channels/leave',
      handler: async (req) => {
        const { entityId: entity_id, body } = await requireEntitySession(ctx, req);
        const { channel_id } = body;
        
        if (!entity_id || !channel_id) {
          return new Response(
            JSON.stringify({ error: 'Missing entity_id or channel_id' }),
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
        validateChannelId(channel_id);
        
        // Check if entity is a member
        if (!ctx.channels.isMember(channel_id, entity_id)) {
          throw new EntityNotInChannelError(entity_id, channel_id);
        }
        
        // Remove member
        ctx.channels.removeMember(channel_id, entity_id);
        
        return new Response(
          JSON.stringify({ ok: true }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      },
    },
    
    // POST /channels/list
    // List channels visible to an entity
    {
      method: 'POST',
      pattern: '/channels/list',
      handler: async (req) => {
        const { entityId: entity_id, body } = await requireEntitySession(ctx, req);
        const { include_public, limit, offset } = body;
        
        if (!entity_id) {
          return new Response(
            JSON.stringify({ error: 'Missing entity_id' }),
            { status: 400, headers: { 'Content-Type': 'application/json' } }
          );
        }
        
        validateEntityId(entity_id);
        
        // Validate pagination params
        const pagination = validatePagination({ limit, offset });
        
        let channels;
        if (include_public !== false) {
          channels = ctx.channels.getVisibleToEntity(entity_id);
        } else {
          channels = ctx.channels.getByMemberId(entity_id);
        }
        
        // Apply pagination
        const total = channels.length;
        const paginatedChannels = channels.slice(pagination.offset, pagination.offset + pagination.limit);
        
        return new Response(
          JSON.stringify({ channels: paginatedChannels, total, limit: pagination.limit, offset: pagination.offset }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      },
    },
    
    // POST /channels/list-members
    // List members of a channel
    {
      method: 'POST',
      pattern: '/channels/list-members',
      handler: async (req) => {
        const { entityId: entity_id, body } = await requireEntitySession(ctx, req);
        const { channel_id } = body;
        
        if (!channel_id) {
          return new Response(
            JSON.stringify({ error: 'Missing channel_id' }),
            { status: 400, headers: { 'Content-Type': 'application/json' } }
          );
        }
        
        validateChannelId(channel_id);
        
        // Verify channel exists
        const channel = ctx.channels.getById(channel_id);
        if (!channel) {
          throw new NotFoundError('Channel', channel_id);
        }

        // A private channel's roster is as disclosive as a directory listing —
        // naming, structure, who works with whom. Public channels are joinable
        // by anyone, so their membership is not a secret; private ones require
        // you to actually be in them. Closing cross-account enumeration on
        // /entities/list while leaving it open here would give two different
        // answers to the same question.
        if (!channel.is_public && !ctx.channels.isMember(channel_id, entity_id)) {
          throw new ForbiddenError('You are not a member of this channel');
        }

        const members = ctx.channels.getMembers(channel_id);

        return new Response(
          JSON.stringify({ members }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      },
    },
    
    // POST /channels/invite
    // Invite an entity to a private channel
    {
      method: 'POST',
      pattern: '/channels/invite',
      handler: async (req) => {
        const { entityId: entity_id, body } = await requireEntitySession(ctx, req);
        const { channel_id, invited_entity } = body;
        
        if (!entity_id || !channel_id || !invited_entity) {
          return new Response(
            JSON.stringify({ error: 'Missing entity_id, channel_id, or invited_entity' }),
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
        validateChannelId(channel_id);
        validateEntityId(invited_entity);
        
        // Verify inviter is a member with owner/admin role
        const channel = ctx.channels.getById(channel_id);
        if (!channel) {
          throw new NotFoundError('Channel', channel_id);
        }
        
        const inviterRole = ctx.channels.getMemberRole(channel_id, entity_id);
        if (!inviterRole || inviterRole === 'member') {
          throw new ForbiddenError('Only channel owners and admins can invite');
        }
        
        // Verify invited entity exists
        const invitedEntity = ctx.entities.getById(invited_entity);
        if (!invitedEntity) {
          throw new NotFoundError('Entity', invited_entity);
        }
        
        // Reject no-op invitations (avoids UNIQUE constraint 500s)
        if (ctx.channels.isMember(channel_id, invited_entity)) {
          return new Response(
            JSON.stringify({ error: 'Entity is already a member of this channel' }),
            { status: 409, headers: { 'Content-Type': 'application/json' } }
          );
        }
        
        const existingInvites = ctx.invitations.getPendingForEntity(invited_entity);
        if (existingInvites.some(i => i.channel_id === channel_id)) {
          return new Response(
            JSON.stringify({ error: 'Invitation already pending for this entity' }),
            { status: 409, headers: { 'Content-Type': 'application/json' } }
          );
        }
        
        // Create invitation
        const invitation = ctx.invitations.create(channel_id, entity_id, invited_entity);
        
        // Push notification to invited entity if they're online
        if (wsManager) {
          wsManager.pushToEntity(invited_entity, {
            type: 'invitation',
            channel_id,
            channel_name: channel.name,
            invited_by: entity_id,
            invited_entity,
            invitation_id: invitation.id,
            timestamp: new Date().toISOString(),
          });
        }
        
        return new Response(
          JSON.stringify({ invitation }),
          { status: 201, headers: { 'Content-Type': 'application/json' } }
        );
      },
    },
    
    // POST /channels/invitations
    // List pending invitations for an entity
    {
      method: 'POST',
      pattern: '/channels/invitations',
      handler: async (req) => {
        const { entityId: entity_id, body } = await requireEntitySession(ctx, req);
        
        if (!entity_id) {
          return new Response(
            JSON.stringify({ error: 'Missing entity_id' }),
            { status: 400, headers: { 'Content-Type': 'application/json' } }
          );
        }
        
        validateEntityId(entity_id);
        
        const invitations = ctx.invitations.getPendingForEntity(entity_id);
        
        return new Response(
          JSON.stringify({ invitations }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      },
    },
    
    // POST /channels/decline-invite
    // Decline a channel invitation
    {
      method: 'POST',
      pattern: '/channels/decline-invite',
      handler: async (req) => {
        const { entityId: entity_id, body } = await requireEntitySession(ctx, req);
        const { invitation_id } = body;
        
        if (!entity_id || !invitation_id) {
          return new Response(
            JSON.stringify({ error: 'Missing entity_id or invitation_id' }),
            { status: 400, headers: { 'Content-Type': 'application/json' } }
          );
        }
        
        validateEntityId(entity_id);
        
        // Verify invitation exists and belongs to this entity
        const invitation = ctx.invitations.getById(invitation_id);
        if (!invitation) {
          throw new NotFoundError('Invitation', invitation_id);
        }
        
        if (invitation.invited_entity !== entity_id) {
          throw new ForbiddenError('This invitation is not for you');
        }
        
        ctx.invitations.decline(invitation_id);
        
        return new Response(
          JSON.stringify({ ok: true }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      },
    },
    
    // POST /channels/kick
    // Kick an entity from a channel (admin/owner only)
    {
      method: 'POST',
      pattern: '/channels/kick',
      handler: async (req) => {
        const { entityId: entity_id, body } = await requireEntitySession(ctx, req);
        const { channel_id, target_entity } = body;
        
        if (!entity_id || !channel_id || !target_entity) {
          return new Response(
            JSON.stringify({ error: 'Missing entity_id, channel_id, or target_entity' }),
            { status: 400, headers: { 'Content-Type': 'application/json' } }
          );
        }
        
        validateEntityId(entity_id);
        validateChannelId(channel_id);
        validateEntityId(target_entity);
        
        // Verify channel exists
        const channel = ctx.channels.getById(channel_id);
        if (!channel) {
          throw new NotFoundError('Channel', channel_id);
        }
        
        // Verify requester has admin/owner role
        const requesterRole = ctx.channels.getMemberRole(channel_id, entity_id);
        if (!requesterRole || requesterRole === 'member') {
          throw new ForbiddenError('Only channel owners and admins can kick members');
        }
        
        // Cannot kick yourself
        if (entity_id === target_entity) {
          throw new ForbiddenError('Cannot kick yourself');
        }
        
        // Verify target is a member
        if (!ctx.channels.isMember(channel_id, target_entity)) {
          throw new EntityNotInChannelError(target_entity, channel_id);
        }
        
        // Cannot kick someone with equal or higher role
        const targetRole = ctx.channels.getMemberRole(channel_id, target_entity);
        if (targetRole === 'owner' || (targetRole === 'admin' && requesterRole !== 'owner')) {
          throw new ForbiddenError('Cannot kick entity with equal or higher role');
        }
        
        ctx.channels.kick(channel_id, target_entity);
        
        // Notify kicked entity if online
        if (wsManager) {
          wsManager.pushToEntity(target_entity, {
            type: 'message',
            from: 'system',
            channel: channel_id,
            to: target_entity,
            text: `You have been kicked from channel "${channel.name}"`,
            timestamp: new Date().toISOString(),
            message_id: 0,
          });
        }
        
        return new Response(
          JSON.stringify({ ok: true }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      },
    },
    
    // POST /channels/set-role
    // Set a member's role (owner only)
    {
      method: 'POST',
      pattern: '/channels/set-role',
      handler: async (req) => {
        const { entityId: entity_id, body } = await requireEntitySession(ctx, req);
        const { channel_id, target_entity, role } = body;
        
        if (!entity_id || !channel_id || !target_entity || !role) {
          return new Response(
            JSON.stringify({ error: 'Missing entity_id, channel_id, target_entity, or role' }),
            { status: 400, headers: { 'Content-Type': 'application/json' } }
          );
        }
        
        if (!['admin', 'member'].includes(role)) {
          return new Response(
            JSON.stringify({ error: 'Role must be "admin" or "member"' }),
            { status: 400, headers: { 'Content-Type': 'application/json' } }
          );
        }
        
        validateEntityId(entity_id);
        validateChannelId(channel_id);
        validateEntityId(target_entity);
        
        // Verify channel exists
        const channel = ctx.channels.getById(channel_id);
        if (!channel) {
          throw new NotFoundError('Channel', channel_id);
        }
        
        // Only owner can set roles
        const requesterRole = ctx.channels.getMemberRole(channel_id, entity_id);
        if (requesterRole !== 'owner') {
          throw new ForbiddenError('Only the channel owner can set roles');
        }
        
        // Verify target is a member
        if (!ctx.channels.isMember(channel_id, target_entity)) {
          throw new EntityNotInChannelError(target_entity, channel_id);
        }
        
        ctx.channels.updateMemberRole(channel_id, target_entity, role);
        
        return new Response(
          JSON.stringify({ ok: true }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      },
    },
  ];
}

