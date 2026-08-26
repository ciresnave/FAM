// Message Repository - CRUD Operations for Messages

import { Database } from 'bun:sqlite';
import type { Message, EntityId, ChannelId } from '../../types';
import {
  encryptMessage,
  decryptMessage,
  keyringFromEnv,
  assertNotSealed,
} from '../../crypto/message-encryption';

// ============================================================================
// Configuration
// ============================================================================

const ENCRYPT_MESSAGES = process.env.FAM_ENCRYPT_MESSAGES === 'true';
// The whole keyring, not just the current secret: after a rotation the backlog
// is still sealed with retired keys and has to stay readable.
const KEYRING = keyringFromEnv();
const SERVER_SECRET = KEYRING.current;

// ============================================================================
// Message Repository
// ============================================================================

export class MessageRepository {
  constructor(private db: Database) {}

  // --------------------------------------------------------------------------
  // Create
  // --------------------------------------------------------------------------

  /**
   * Send a direct message to an entity.
   */
  async sendDirectMessage(fromEntityId: EntityId, toEntityId: EntityId, text: string): Promise<Message> {
    const encryptedText = ENCRYPT_MESSAGES && SERVER_SECRET
      ? await encryptMessage(text, KEYRING)
      : text;
    
    const stmt = this.db.prepare(`
      INSERT INTO messages (from_entity, to_entity, text)
      VALUES (?, ?, ?)
    `);

    const result = stmt.run(fromEntityId, toEntityId, encryptedText);
    const messageId = result.lastInsertRowid as number;

    // One recipient, recorded explicitly so acknowledgement is per-entity.
    this.db
      .prepare(
        `INSERT OR IGNORE INTO message_deliveries (message_id, recipient_entity_id) VALUES (?, ?)`
      )
      .run(messageId, toEntityId);

    const msg = this.getByIdRaw(messageId)!;
    // Return with original text for immediate use
    return { ...msg, text };
  }

  /**
   * Send a message to a channel.
   */
  async sendChannelMessage(fromEntityId: EntityId, channelId: ChannelId, text: string): Promise<Message> {
    const encryptedText = ENCRYPT_MESSAGES && SERVER_SECRET
      ? await encryptMessage(text, KEYRING)
      : text;
    
    const stmt = this.db.prepare(`
      INSERT INTO messages (from_entity, channel_id, text)
      VALUES (?, ?, ?)
    `);

    const result = stmt.run(fromEntityId, channelId, encryptedText);
    const messageId = result.lastInsertRowid as number;

    // Fan out to the members as they are AT SEND TIME, excluding the sender.
    // Doing this on send rather than on read is what stops a later joiner
    // inheriting history that was never addressed to them.
    this.db
      .prepare(
        `INSERT OR IGNORE INTO message_deliveries (message_id, recipient_entity_id)
         SELECT ?, entity_id FROM channel_members
         WHERE channel_id = ? AND entity_id != ?`
      )
      .run(messageId, channelId, fromEntityId);

    const msg = this.getByIdRaw(messageId)!;
    // Return with original text for immediate use
    return { ...msg, text };
  }

  // --------------------------------------------------------------------------
  // Read
  // --------------------------------------------------------------------------

  /**
   * Get message by ID with decrypted text.
   * When FAM_ENCRYPT_MESSAGES=true the stored ciphertext is transparently
   * decrypted. Prefer this for any caller that reads `text`.
   */
  async getById(id: number): Promise<Message | null> {
    const raw = this.getByIdRaw(id);
    if (!raw) return null;
    const [decrypted] = await this.decryptMessages([raw]);
    return decrypted ?? raw;
  }

  /**
   * Get the raw database row for a message.
   * When FAM_ENCRYPT_MESSAGES=true the `text` field contains ciphertext —
   * use only for ownership/metadata checks that never read `text`.
   */
  getByIdRaw(id: number): Message | null {
    const stmt = this.db.prepare(`
      SELECT * FROM messages WHERE id = ?
    `);

    return stmt.get(id) as Message | null;
  }

  /**
   * Get undelivered messages for an entity.
   * Returns both DMs and channel messages.
   */
  async getUndelivered(entityId: EntityId, limit: number = 100): Promise<Message[]> {
    // One indexed lookup rather than a DM query unioned with a
    // channel-membership query. It also no longer depends on CURRENT channel
    // membership: rows exist only for the members a message was actually
    // fanned out to at send time.
    const stmt = this.db.prepare(`
      SELECT m.* FROM messages m
      JOIN message_deliveries d ON d.message_id = m.id
      WHERE d.recipient_entity_id = ? AND d.delivered = 0
      ORDER BY m.sent_at ASC
      LIMIT ?
    `);

    const messages = stmt.all(entityId, limit) as Message[];
    return this.decryptMessages(messages);
  }

  /**
   * Get message history for a direct message conversation.
   */
  async getDirectMessageHistory(
    entityId1: EntityId,
    entityId2: EntityId,
    limit: number = 50
  ): Promise<Message[]> {
    const stmt = this.db.prepare(`
      SELECT * FROM messages
      WHERE (from_entity = ? AND to_entity = ?)
         OR (from_entity = ? AND to_entity = ?)
      ORDER BY sent_at DESC
      LIMIT ?
    `);

    const messages = stmt.all(entityId1, entityId2, entityId2, entityId1, limit) as Message[];
    return this.decryptMessages(messages);
  }

  /**
   * Get message history for a channel.
   */
  async getChannelHistory(channelId: ChannelId, limit: number = 50): Promise<Message[]> {
    const stmt = this.db.prepare(`
      SELECT * FROM messages
      WHERE channel_id = ?
      ORDER BY sent_at DESC
      LIMIT ?
    `);

    const messages = stmt.all(channelId, limit) as Message[];
    return this.decryptMessages(messages);
  }

  // --------------------------------------------------------------------------
  // Update
  // --------------------------------------------------------------------------

  /**
   * Filter a list of message IDs down to those the entity owns
   * (DMs addressed to them, or messages to channels they belong to).
   * Single query — used for batch delivered-acknowledgment validation.
   */
  getOwnedMessageIds(entityId: EntityId, messageIds: number[]): number[] {
    if (messageIds.length === 0) return [];

    const placeholders = messageIds.map(() => '?').join(',');
    // Having a delivery row IS being a recipient — no separate ownership rule
    // to keep in step, and a membership change cannot retroactively grant or
    // revoke the right to acknowledge a past message.
    const stmt = this.db.prepare(`
      SELECT message_id AS id FROM message_deliveries
      WHERE recipient_entity_id = ? AND message_id IN (${placeholders})
    `);

    const rows = stmt.all(entityId, ...messageIds) as Array<{ id: number }>;
    return rows.map(r => r.id);
  }

  /**
   * Mark messages delivered FOR ONE RECIPIENT.
   *
   * Takes the acknowledging entity deliberately. The previous signature had no
   * recipient at all, which is exactly what made one member's acknowledgement
   * hide a channel message from every other member.
   */
  markDelivered(entityId: EntityId, messageIds: number[]): void {
    if (messageIds.length === 0) return;

    const placeholders = messageIds.map(() => '?').join(',');
    const stmt = this.db.prepare(`
      UPDATE message_deliveries
      SET delivered = 1, delivered_at = datetime('now')
      WHERE recipient_entity_id = ? AND message_id IN (${placeholders})
    `);

    stmt.run(entityId, ...messageIds);
  }

  /**
   * Mark all undelivered messages for an entity as delivered.
   */
  markAllDelivered(entityId: EntityId): void {
    const stmt = this.db.prepare(`
      UPDATE message_deliveries
      SET delivered = 1, delivered_at = datetime('now')
      WHERE recipient_entity_id = ? AND delivered = 0
    `);

    stmt.run(entityId);
  }

  // --------------------------------------------------------------------------
  // Delete
  // --------------------------------------------------------------------------

  /**
   * Delete a message.
   */
  delete(id: number): void {
    const stmt = this.db.prepare(`
      DELETE FROM messages WHERE id = ?
    `);

    stmt.run(id);
  }

  /**
   * Delete all messages for a channel.
   */
  deleteByChannelId(channelId: ChannelId): void {
    const stmt = this.db.prepare(`
      DELETE FROM messages WHERE channel_id = ?
    `);

    stmt.run(channelId);
  }

  /**
   * Delete messages older than specified days.
   */
  deleteOlderThan(days: number): number {
    const stmt = this.db.prepare(`
      DELETE FROM messages
      WHERE sent_at < datetime('now', '-' || ? || ' days')
    `);

    const result = stmt.run(days);
    return result.changes;
  }

  // --------------------------------------------------------------------------
  // Stats
  // --------------------------------------------------------------------------

  /**
   * Get message count.
   */
  getCount(): number {
    const stmt = this.db.prepare(`
      SELECT COUNT(*) as count FROM messages
    `);

    const result = stmt.get() as { count: number };
    return result.count;
  }

  /**
   * Get undelivered count for an entity.
   */
  getUndeliveredCount(entityId: EntityId): number {
    const stmt = this.db.prepare(`
      SELECT COUNT(*) as count FROM message_deliveries
      WHERE recipient_entity_id = ? AND delivered = 0
    `);

    const result = stmt.get(entityId) as { count: number };
    return result.count;
  }
  
  // --------------------------------------------------------------------------
  // Encryption Helpers
  // --------------------------------------------------------------------------
  
  /**
   * Decrypt messages if encryption is enabled.
   */
  private async decryptMessages(messages: Message[]): Promise<Message[]> {
    if (!ENCRYPT_MESSAGES || !SERVER_SECRET) {
      // Encryption is off, but rows written while it was ON are still
      // ciphertext. Without this the envelope JSON is returned AS the message
      // text and shown to a person as if someone had written it — a silent
      // failure, and the only one of the two toggle directions that produces
      // no error at all.
      assertNotSealed(messages);
      return messages;
    }
    
    return Promise.all(
      messages.map(async (msg) => ({
        ...msg,
        text: await decryptMessage(msg.text, KEYRING),
      }))
    );
  }
}
