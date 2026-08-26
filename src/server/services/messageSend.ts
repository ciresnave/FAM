// Message Send Service
//
// Single authoritative path for sending messages (DM + channel).
// Both the HTTP route (/messages/send) and the WebSocket send handler
// delegate here so that validation, persistence, and push behavior are
// identical — and so future enforcement (permission matrix, availability)
// has exactly one place to live.

import type { DatabaseContext } from '../../db/transaction';
import type { WebSocketManager } from '../websocket';
import type { Message, EntityId, ChannelId } from '../../types';
import { NotFoundError, ForbiddenError, InsufficientCapabilitiesError, EntityNotInChannelError } from '../../types/errors';
import { validateEntityId, validateChannelId, validateMessageText } from '../../types/validation';
import type { PermissionChecker } from './permissionChecker';

// ============================================================================
// Message Send Service
// ============================================================================

export class MessageSendService {
  constructor(
    private ctx: DatabaseContext,
    private wsManager: WebSocketManager,
    private permissionChecker: PermissionChecker
  ) {}

  /**
   * Send a direct message from one entity to another.
   * Enforces the permission policy (default-deny cross-account; deny rules
   * revoke). Persists, then pushes to the recipient if online.
   * Throws FamError subclasses on validation/authorization failure.
   */
  async sendDirectMessage(
    fromEntityId: EntityId,
    toEntityId: EntityId,
    text: string
  ): Promise<Message> {
    validateEntityId(fromEntityId);
    validateEntityId(toEntityId);
    validateMessageText(text);

    const sender = this.requireSender(fromEntityId);

    const recipient = this.ctx.entities.getById(toEntityId);
    if (!recipient) {
      throw new NotFoundError('Entity', toEntityId);
    }

    if (!this.permissionChecker.canDirectMessage(sender, recipient)) {
      throw new ForbiddenError('Not permitted to message this entity');
    }

    const trimmed = text.trim();

    // Encrypt BEFORE the authorizing check, then check and insert with no
    // await between them. Previously the check ran, the persist was awaited,
    // and a revocation landing in that window still produced a stored message
    // — the grant said no by the time the row existed.
    const storedText = await this.ctx.messages.prepareStoredText(trimmed);

    const message = this.ctx.db.transaction(() => {
      if (!this.permissionChecker.canDirectMessage(sender, recipient)) {
        throw new ForbiddenError('Not permitted to message this entity');
      }
      return this.ctx.messages.insertDirectMessage(fromEntityId, toEntityId, storedText, trimmed);
    })();

    // Push to recipient if online
    this.wsManager.pushToEntity(toEntityId, {
      type: 'message',
      from: fromEntityId,
      channel: null,
      to: toEntityId,
      text: trimmed,
      timestamp: message.sent_at,
      message_id: message.id,
    });

    return message;
  }

  /**
   * Send a message to a channel.
   * Channel membership implies allow (joining opts into messages from
   * members); explicit deny rules on a member's account still filter pushes
   * to that member. Persists once, then pushes to eligible online members
   * except the sender.
   * Throws FamError subclasses on validation/authorization failure.
   */
  async sendChannelMessage(
    fromEntityId: EntityId,
    channelId: ChannelId,
    text: string
  ): Promise<Message> {
    validateEntityId(fromEntityId);
    validateChannelId(channelId);
    validateMessageText(text);

    this.requireSender(fromEntityId);

    const channel = this.ctx.channels.getById(channelId);
    if (!channel) {
      throw new NotFoundError('Channel', channelId);
    }

    if (!this.ctx.channels.isMember(channelId, fromEntityId)) {
      throw new EntityNotInChannelError(fromEntityId, channelId);
    }

    const sender = this.ctx.entities.getById(fromEntityId)!;

    const trimmed = text.trim();

    // Same ordering as a DM: the membership that authorizes this send is
    // re-checked with no await between the check and the row.
    const storedText = await this.ctx.messages.prepareStoredText(trimmed);

    const message = this.ctx.db.transaction(() => {
      if (!this.ctx.channels.isMember(channelId, fromEntityId)) {
        throw new EntityNotInChannelError(fromEntityId, channelId);
      }
      return this.ctx.messages.insertChannelMessage(fromEntityId, channelId, storedText, trimmed);
    })();

    // Push to online channel members except the sender, skipping members
    // whose account has denied this sender by rule
    const pushMessage = {
      type: 'message' as const,
      from: fromEntityId,
      channel: channelId,
      to: null,
      text: trimmed,
      timestamp: message.sent_at,
      message_id: message.id,
    };

    const members = this.ctx.channels.getMembers(channelId);
    for (const member of members) {
      if (member.entity_id === fromEntityId) continue;

      const memberEntity = this.ctx.entities.getById(member.entity_id);
      if (!memberEntity) continue;

      if (this.permissionChecker.isDeniedByRules(sender, memberEntity)) continue;

      this.wsManager.pushToEntity(member.entity_id, pushMessage);
    }

    return message;
  }

  // --------------------------------------------------------------------------
  // Internal
  // --------------------------------------------------------------------------

  private requireSender(entityId: EntityId) {
    const sender = this.ctx.entities.getById(entityId);
    if (!sender) {
      throw new NotFoundError('Entity', entityId);
    }
    if (!sender.capabilities.can_send) {
      throw new InsufficientCapabilitiesError('can_send');
    }
    return sender;
  }
}
