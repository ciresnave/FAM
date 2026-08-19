// Message Repository - CRUD Operations for Messages

import { Database } from 'bun:sqlite';
import type { Message, EntityId, ChannelId } from '../../types';
import { encryptMessage, decryptMessage } from '../../crypto/message-encryption';

// ============================================================================
// Configuration
// ============================================================================

const ENCRYPT_MESSAGES = process.env.FAM_ENCRYPT_MESSAGES === 'true';
const SERVER_SECRET = process.env.FAM_SERVER_SECRET || '';

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
      ? await encryptMessage(text, SERVER_SECRET)
      : text;
    
    const stmt = this.db.prepare(`
      INSERT INTO messages (from_entity, to_entity, text)
      VALUES (?, ?, ?)
    `);

    const result = stmt.run(fromEntityId, toEntityId, encryptedText);
    const messageId = result.lastInsertRowid as number;

    const msg = this.getByIdRaw(messageId)!;
    // Return with original text for immediate use
    return { ...msg, text };
  }

  /**
   * Send a message to a channel.
   */
  async sendChannelMessage(fromEntityId: EntityId, channelId: ChannelId, text: string): Promise<Message> {
    const encryptedText = ENCRYPT_MESSAGES && SERVER_SECRET
      ? await encryptMessage(text, SERVER_SECRET)
      : text;
    
    const stmt = this.db.prepare(`
      INSERT INTO messages (from_entity, channel_id, text)
      VALUES (?, ?, ?)
    `);

    const result = stmt.run(fromEntityId, channelId, encryptedText);
    const messageId = result.lastInsertRowid as number;

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
    // Get direct messages
    const dmStmt = this.db.prepare(`
      SELECT * FROM messages
      WHERE to_entity = ? AND delivered = 0
      ORDER BY sent_at ASC
      LIMIT ?
    `);

    const dms = dmStmt.all(entityId, limit) as Message[];

    // Get channel messages for channels the entity is in
    const channelStmt = this.db.prepare(`
      SELECT m.* FROM messages m
      JOIN channel_members cm ON m.channel_id = cm.channel_id
      WHERE cm.entity_id = ? AND m.from_entity != ? AND m.delivered = 0
      ORDER BY m.sent_at ASC
      LIMIT ?
    `);

    const channelMessages = channelStmt.all(entityId, entityId, limit) as Message[];

    // Combine and sort by time
    const allMessages = [...dms, ...channelMessages].sort(
      (a, b) => new Date(a.sent_at).getTime() - new Date(b.sent_at).getTime()
    ).slice(0, limit);
    
    // Decrypt if needed
    return this.decryptMessages(allMessages);
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
    const stmt = this.db.prepare(`
      SELECT id FROM messages
      WHERE id IN (${placeholders})
      AND (
        to_entity = ?
        OR channel_id IN (SELECT channel_id FROM channel_members WHERE entity_id = ?)
      )
    `);

    const rows = stmt.all(...messageIds, entityId, entityId) as Array<{ id: number }>;
    return rows.map(r => r.id);
  }

  /**
   * Mark messages as delivered.
   */
  markDelivered(messageIds: number[]): void {
    if (messageIds.length === 0) return;

    const placeholders = messageIds.map(() => '?').join(',');
    const stmt = this.db.prepare(`
      UPDATE messages SET delivered = 1
      WHERE id IN (${placeholders})
    `);

    stmt.run(...messageIds);
  }

  /**
   * Mark all undelivered messages for an entity as delivered.
   */
  markAllDelivered(entityId: EntityId): void {
    const stmt = this.db.prepare(`
      UPDATE messages SET delivered = 1
      WHERE (to_entity = ? OR channel_id IN (
        SELECT channel_id FROM channel_members WHERE entity_id = ?
      )) AND delivered = 0
    `);

    stmt.run(entityId, entityId);
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
      SELECT COUNT(*) as count FROM messages
      WHERE (to_entity = ? OR channel_id IN (
        SELECT channel_id FROM channel_members WHERE entity_id = ?
      )) AND delivered = 0
    `);

    const result = stmt.get(entityId, entityId) as { count: number };
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
      return messages;
    }
    
    return Promise.all(
      messages.map(async (msg) => ({
        ...msg,
        text: await decryptMessage(msg.text, SERVER_SECRET),
      }))
    );
  }
}
