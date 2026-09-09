// Channel Push Handler for MCP Adapter
//
// Listens for FAM WebSocket messages and pushes them as MCP channel notifications.
// This is the key integration point that makes messages appear immediately in Claude Code.

import type { Server } from '@modelcontextprotocol/sdk/server/index.js';
import type { FamClient, AuthenticateResponse } from './client';
import type { WebSocketMessagePush, EntityId } from '../../types';
import { readIncoming } from '../../messaging/receive';
import { resolveSenderIdentity } from '../../messaging/senderIdentity';
import { getPeerAnchorKey } from '../cli/peerAnchors';
import { loadSeen, recordSeen, REPLAY_WINDOW_MS } from '../cli/seenMessages';

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
  /**
   * Where the local trust and replay stores live.
   *
   * ⚠️ INJECTABLE BECAUSE THE DEFAULTS ARE THE USER'S REAL HOME DIRECTORY, and
   * a test that does not override them WRITES THERE. That is not hypothetical:
   * this handler recorded `alice@example.com` into a developer's actual
   * `~/.fam/seen-messages.json` during a test run, and the NEXT run read it
   * back and refused a fixture as a replay. The suite passed once and then
   * failed, with the cause sitting outside the repository entirely.
   *
   * The undefined default is deliberate rather than a path constant: passing
   * `undefined` through to the store keeps ONE definition of where the real
   * files are, instead of a second copy here that could drift.
   */
  private stores: { seenPath?: string; anchorsPath?: string };

  constructor(
    mcp: Server,
    client: FamClient,
    entityDisplayName: string,
    encryptionPrivateKey: string | null = null,
    entityId: string | null = null,
    stores: { seenPath?: string; anchorsPath?: string } = {}
  ) {
    this.mcp = mcp;
    this.client = client;
    this.entityDisplayName = entityDisplayName;
    this.encryptionPrivateKey = encryptionPrivateKey;
    this.entityId = entityId;
    this.stores = stores;
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
   * Which key may this sender's signature be checked against?
   *
   * ⚠️ THE DIRECTORY IS THE RELAY'S WORD. `entities.public_key` is a column in
   * the server's own database; a malicious home server needs nobody's private
   * key to forge, it simply publishes its own. So the directory value is an
   * INPUT to `resolveSenderIdentity`, never the answer — and a chain that
   * resolves to a DIFFERENT key refuses outright, because that disagreement is
   * the attack rather than a preference.
   *
   * The decision lives in `senderIdentity.ts` so this adapter and the CLI
   * cannot answer it differently. Only the gathering is here.
   */
  private async identityFor(entityId: string) {
    const at = entityId.indexOf('@');
    const accountId = at === -1 ? entityId : entityId.slice(at + 1);

    const accountPublicKey = await getPeerAnchorKey(accountId, this.stores.anchorsPath);
    const serverSuppliedKey = (await this.senderKeyFor(entityId)) || null;

    let records: any[] = [];
    if (accountPublicKey) {
      try {
        records = await this.client.listVoucherRecords(entityId);
      } catch {
        // A relay that will not answer produces `unvouched`, never a pass.
        records = [];
      }
    }

    return resolveSenderIdentity({ entityId, serverSuppliedKey, accountPublicKey, records });
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
  
  /**
   * Open one incoming message, or explain why it could not be opened.
   *
   * ⚠️ SHARED BY THE LIVE PATH AND THE BACKLOG PATH, AND THAT IS THE POINT.
   * This logic used to live inside `handleMessage` only. `handleUndelivered` —
   * its sibling, twenty lines below — pushed `text` straight through, so the
   * offline path had no decryption, no signature check, no replay window and no
   * `sealed` flag. The envelope JSON was observed arriving in a real client's
   * context.
   *
   * The instance was one missing call. The CLASS is that two branches of one
   * decision were written separately, so the fix is not to add the guard to the
   * second branch — it is to leave only one branch to guard. Four instances of
   * that shape were measured in this repository in a single day.
   *
   * ⚠️ OPENED BEFORE IT IS PUSHED, AND WITHHELD IF IT CANNOT BE VERIFIED.
   * `text` for a sealed message is the ENVELOPE — pushing it unopened puts JSON
   * into an agent's context as though someone had written it. And because anyone
   * can seal to a published key, decrypting proves only that the message was
   * addressed here; the signature is what says who wrote it.
   */
  private async openIncoming(
    from: EntityId,
    text: string,
    sealed: boolean
  ): Promise<{ content: string; vouched: boolean; deliverable: boolean }> {
    const identity = sealed
      ? await this.identityFor(from)
      : ({ kind: 'unvouched', publicKey: '' } as const);

    if (identity.kind === 'refused') {
      // ⚠️ NOTHING IS OPENED. Either the sender could not be established, or
      // they were and the answer CONTRADICTS the key the relay served.
      return { content: `[not shown] ${identity.reason}`, vouched: false, deliverable: false };
    }

    const now = new Date();
    const read = await readIncoming(
      { sealed, text, from_entity: from },
      {
        recipientEncryptionPrivateKey: this.encryptionPrivateKey,
        senderIdentityPublicKey: identity.publicKey,
        // Required for a CHANNEL message: the group envelope wraps the content
        // key once per member, selected by entity id.
        recipientEntityId: this.entityId,
        replay: {
          seen: await loadSeen(now, REPLAY_WINDOW_MS, this.stores.seenPath),
          now,
          windowMs: REPLAY_WINDOW_MS,
        },
      }
    );

    if (read.kind === 'opened' && read.seen) {
      // Recorded only after it OPENED. A message that could not be read is not
      // evidence of delivery, and recording it would make a genuine retry look
      // like a replay.
      await recordSeen(read.seen, now, REPLAY_WINDOW_MS, this.stores.seenPath);
    }

    const withheld = read.kind === 'unreadable' || read.kind === 'replayed';

    // ⚠️ `deliverable` IS NOT `kind === 'opened'`, AND THE DIFFERENCE IS A
    // DATA-LOSS BUG IN EITHER DIRECTION. It gates whether a backlog row may be
    // acknowledged, so:
    //
    //   plaintext   delivered — an unsealed message needed no opening
    //   opened      delivered
    //   replayed    ALREADY delivered. Withholding the ack here would re-offer
    //               it on every reconnect, forever, rendering "[not shown]
    //               replayed" into an agent's context each time — a permanent
    //               noise floor on the path whose whole job is to be quiet.
    //   unreadable  NOT delivered. The key may arrive later; acking destroys it.
    //
    // The first draft used `kind === 'opened'` and a test on a mixed batch
    // caught it: a plain message would never have been acknowledged.
    return {
      content: withheld ? `[not shown] ${read.reason}` : read.text,
      vouched: identity.kind === 'vouched',
      deliverable: read.kind !== 'unreadable',
    };
  }

  private handleMessage = async (message: WebSocketMessagePush): Promise<void> => {
    try {
      const senderInfo = this.buildSenderInfo(message);

      const { content, vouched } = await this.openIncoming(
        message.from,
        message.text,
        message.sealed === true
      );

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
        // Whether the SENDER key was vouched for by their account, or is still
        // the relay's word. An agent acting on a message deserves to know which.
        sender_vouched: vouched,
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
      // ⚠️ ACKNOWLEDGE ONLY WHAT WAS ACTUALLY DELIVERED, not the whole batch.
      //
      // This used to be `markDelivered(messages.map(m => m.id))` — every id,
      // unconditionally, straight after pushing. Two ways that destroyed mail:
      //
      //   the push THREW          a closed stdio pipe raises EPIPE; the message
      //                           reached nobody and was marked delivered anyway
      //   it could not be OPENED  a sealed message with no usable key rendered
      //                           "[not shown] …" and was then acked, so it
      //                           could never be re-read once the key arrived
      //
      // Both are now excluded. A message stays undelivered and is offered again.
      const delivered: number[] = [];

      for (const message of messages) {
        const senderInfo = this.buildSenderInfo({ from: message.from_entity });

        const { content, vouched, deliverable } = await this.openIncoming(
          message.from_entity,
          message.text,
          message.sealed === true
        );

        await this.pushChannelNotification(content, {
          from_entity: message.from_entity,
          from_display_name: senderInfo.displayName,
          channel: message.channel_id,
          sent_at: message.sent_at,
          message_id: message.id,
          sealed: message.sealed === true,
          sender_vouched: vouched,
          offline_backlog: true,
        });

        // Reached only if the push did not throw.
        if (deliverable) delivered.push(message.id);
      }

      if (delivered.length > 0) {
        await this.client.markDelivered(delivered);
      }
      if (messages.length > 0) {
        console.error(
          `[fam-push] Pushed ${messages.length} offline backlog message(s), ` +
            `acknowledged ${delivered.length}`
        );
      }

      // ⚠️ THE RESIDUAL, AND IT CANNOT BE FIXED HERE.
      //
      // An MCP notification carries no acknowledgement by protocol — no id, no
      // response. `pushChannelNotification` resolving means "written to the
      // pipe". So this code can detect a DEAD pipe but NOT a live pipe that
      // nobody is reading: a client which authenticates without registering a
      // handler for `notifications/claude/channel` still consumes its backlog,
      // silently on both sides. Measured against a real Python MCP client, which
      // drops an unbound notification at `logger.debug`.
      //
      // The real fix is that the ACK MUST BELONG TO THE RECEIVER, and the server
      // already says so in prose at routes/entities.ts — "the client must
      // acknowledge via /messages/delivered after processing". Doing that here
      // needs a tool the client calls, which is a contract change this system is
      // not getting. Recorded in DESIGN-SYNAPSE-HANDOVER.md as a requirement on
      // the replacement rather than left as a surprise.
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
