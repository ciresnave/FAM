// Channel Push Handler for MCP Adapter
//
// Listens for FAM WebSocket messages and pushes them as MCP channel notifications.
// This is the key integration point that makes messages appear immediately in Claude Code.

import type { Server } from '@modelcontextprotocol/sdk/server/index.js';
import type { FamClient, AuthenticateResponse } from './client';
import type { WebSocketMessagePush } from '../../types';
import { readIncoming } from '../../messaging/receive';

// ============================================================================
// Channel Push Handler
// ============================================================================

export class ChannelPushHandler {
  private mcp: Server;
  private client: FamClient;
  private entityDisplayName: string;
  /**
   * This entity's X25519 private half, or null if it has never published one.
   *
   * Null is a real state, not a misconfiguration: an entity created before
   * encryption keys existed cannot open sealed mail, and the recipient is told
   * that specifically rather than being shown a damaged-message error.
   */
  private encryptionPrivateKey: string | null;
  /** This entity's own id, needed to select its wrapped key in a group envelope. */
  private entityId: string | null;

  constructor(
    mcp: Server,
    client: FamClient,
    entityDisplayName: string,
    encryptionPrivateKey: string | null = null,
    entityId: string | null = null
  ) {
    this.mcp = mcp;
    this.client = client;
    this.entityDisplayName = entityDisplayName;
    this.encryptionPrivateKey = encryptionPrivateKey;
    this.entityId = entityId;
  }

  /**
   * The claimed sender's identity key, from the directory.
   *
   * ⚠️ FETCHED FRESH RATHER THAN CACHED AT STARTUP. An entity that joins after
   * this process began would otherwise be permanently unverifiable, and the
   * outcome of "sender not in my cache" is that their messages are never shown.
   * A miss here is a silent mute, so it must not be caused by staleness.
   */
  private async senderKeyFor(entityId: string): Promise<string> {
    try {
      const entities = await this.client.listEntities();
      return entities.find((e) => e.id === entityId)?.public_key ?? '';
    } catch {
      return '';
    }
  }
  
  /**
   * Start listening for FAM messages and pushing to MCP.
   */
  start(): void {
    this.client.onMessage(this.handleMessage);
    this.client.onUndeliveredMessages(this.handleUndelivered);
    this.client.onInvitation(this.handleInvitation);
  }
  
  /**
   * Stop listening for messages.
   */
  stop(): void {
    this.client.offMessage(this.handleMessage);
    this.client.offUndeliveredMessages(this.handleUndelivered);
    this.client.offInvitation(this.handleInvitation);
  }
  
  /**
   * Handle incoming FAM message and push to MCP channel.
   */
  private async pushChannelNotification(content: string, meta: Record<string, unknown>): Promise<void> {
    await this.mcp.notification({
      method: 'notifications/claude/channel',
      params: {
        content,
        meta,
      },
    });
  }
  
  private handleMessage = async (message: WebSocketMessagePush): Promise<void> => {
    try {
      const senderInfo = this.buildSenderInfo(message);

      // ⚠️ OPENED BEFORE IT IS PUSHED, AND WITHHELD IF IT CANNOT BE VERIFIED.
      // The push already carries `sealed`, and `text` for a sealed message is
      // the ENVELOPE — pushing it unopened puts JSON into an agent's context as
      // though someone had written it. And because anyone can seal to a
      // published key, decrypting proves only that the message was addressed
      // here; the signature is what says who wrote it.
      const read = await readIncoming(
        { sealed: message.sealed, text: message.text, from_entity: message.from },
        {
          recipientEncryptionPrivateKey: this.encryptionPrivateKey,
          senderIdentityPublicKey: message.sealed ? await this.senderKeyFor(message.from) : '',
          // Required for a CHANNEL message: the group envelope wraps the
          // content key once per member, selected by entity id.
          recipientEntityId: this.entityId,
        }
      );

      const content =
        read.kind === 'unreadable' ? `[not shown] ${read.reason}` : read.text;

      await this.pushChannelNotification(content, {
        from_entity: message.from,
        from_display_name: senderInfo.displayName,
        channel: message.channel,
        sent_at: message.timestamp,
        message_id: message.message_id,
        // Carried through, not dropped. The core stored the references and the
        // frame delivered them; discarding them HERE meant a reference survived
        // everywhere except the one place a recipient reads — a data-loss path
        // inside the feature built to stop references going missing.
        refs: (message as any).refs,
        sealed: message.sealed === true,
      });

      // The LOG shows the rendered content, never `message.text` — that field is
      // the envelope for a sealed message, and stderr is still somewhere it
      // should not be written.
      console.error(`[fam-push] Pushed message from ${message.from}: ${content.slice(0, 80)}`);
      
      // Mark as delivered — but not for system notifications (kick/ban notices
      // use message_id: 0 and are not persisted in the messages table)
      if (message.message_id > 0) {
        await this.client.markDelivered([message.message_id]);
      }
      
    } catch (e) {
      console.error('[fam-push] Failed to push message:', e);
    }
  };
  
  private handleUndelivered = async (messages: AuthenticateResponse['undelivered_messages']): Promise<void> => {
    try {
      for (const message of messages) {
        const senderInfo = this.buildSenderInfo({ from: message.from_entity });
        
        await this.pushChannelNotification(message.text, {
          from_entity: message.from_entity,
          from_display_name: senderInfo.displayName,
          channel: message.channel_id,
          sent_at: message.sent_at,
          message_id: message.id,
          offline_backlog: true,
        });
      }
      
      if (messages.length > 0) {
        // Mark backlog as delivered
        await this.client.markDelivered(messages.map(m => m.id));
        console.error(`[fam-push] Pushed ${messages.length} offline backlog message(s)`);
      }
    } catch (e) {
      console.error('[fam-push] Failed to push undelivered messages:', e);
    }
  };
  
  private handleInvitation = async (invitation: { channel_id: string; channel_name: string; invited_by: string; invitation_id: string }): Promise<void> => {
    try {
      await this.pushChannelNotification(
        `You have been invited to channel "${invitation.channel_name}" by ${invitation.invited_by}. Use fam_join_channel with channel_id ${invitation.channel_id} to join.`,
        {
          from_entity: invitation.invited_by,
          channel: invitation.channel_id,
          notification_type: 'invitation',
          invitation_id: invitation.invitation_id,
        }
      );
      
      console.error(`[fam-push] Pushed invitation to channel ${invitation.channel_name}`);
    } catch (e) {
      console.error('[fam-push] Failed to push invitation:', e);
    }
  };
  
  /**
   * Build sender info for display.
   */
  private buildSenderInfo(message: { from: string }): { displayName: string } {
    const parts = message.from.split('@');
    return {
      displayName: parts[0] || message.from,
    };
  }
}
