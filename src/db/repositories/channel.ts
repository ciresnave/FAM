// Channel Repository - CRUD Operations for Channels

import { Database } from 'bun:sqlite';
import { randomUUID } from 'crypto';
import type { Channel, ChannelId, EntityId, ChannelMember, ChannelMemberRole } from '../../types';

// ============================================================================
// Channel Repository
// ============================================================================

export class ChannelRepository {
  constructor(private db: Database) {}

  // --------------------------------------------------------------------------
  // Create
  // --------------------------------------------------------------------------

  /**
   * Create a new channel.
   * Uses a transaction to ensure channel + owner member are created atomically.
   */
  create(name: string, createdByEntityId: EntityId, isPublic: boolean = false): Channel {
    const id = randomUUID();

    const createChannel = this.db.prepare(`
      INSERT INTO channels (id, name, created_by_entity, is_public)
      VALUES (?, ?, ?, ?)
    `);

    const addOwner = this.db.prepare(`
      INSERT INTO channel_members (channel_id, entity_id, role)
      VALUES (?, ?, ?)
    `);

    // Transaction: create channel + add owner
    this.db.run('BEGIN');
    try {
      createChannel.run(id, name, createdByEntityId, isPublic ? 1 : 0);
      addOwner.run(id, createdByEntityId, 'owner');
      this.db.run('COMMIT');
    } catch (e) {
      this.db.run('ROLLBACK');
      throw e;
    }

    return this.getById(id)!;
  }

  // --------------------------------------------------------------------------
  // Read
  // --------------------------------------------------------------------------

  /**
   * Get channel by ID.
   */
  getById(id: ChannelId): Channel | null {
    const stmt = this.db.prepare(`
      SELECT * FROM channels WHERE id = ?
    `);

    const row = stmt.get(id) as any;
    if (!row) return null;

    return this.mapRowToChannel(row);
  }

  /**
   * Get all channels visible to an entity.
   * Includes: public channels + channels the entity is a member of.
   */
  getVisibleToEntity(entityId: EntityId): Channel[] {
    const stmt = this.db.prepare(`
      SELECT DISTINCT c.* FROM channels c
      LEFT JOIN channel_members cm ON c.id = cm.channel_id
      WHERE c.is_public = 1 OR cm.entity_id = ?
    `);

    const rows = stmt.all(entityId) as any[];
    return rows.map(this.mapRowToChannel);
  }

  /**
   * Get all public channels.
   */
  getPublic(): Channel[] {
    const stmt = this.db.prepare(`
      SELECT * FROM channels WHERE is_public = 1
    `);

    const rows = stmt.all() as any[];
    return rows.map(this.mapRowToChannel);
  }

  /**
   * Get channels where entity is a member.
   */
  getByMemberId(entityId: EntityId): Channel[] {
    const stmt = this.db.prepare(`
      SELECT c.* FROM channels c
      JOIN channel_members cm ON c.id = cm.channel_id
      WHERE cm.entity_id = ?
    `);

    const rows = stmt.all(entityId) as any[];
    return rows.map(this.mapRowToChannel);
  }

  // --------------------------------------------------------------------------
  // Members
  // --------------------------------------------------------------------------

  /**
   * Add member to channel.
   */
  addMember(channelId: ChannelId, entityId: EntityId, role: ChannelMemberRole = 'member'): ChannelMember {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO channel_members (channel_id, entity_id, role)
      VALUES (?, ?, ?)
    `);

    stmt.run(channelId, entityId, role);

    return { channel_id: channelId, entity_id: entityId, role, joined_at: new Date().toISOString() };
  }

  /**
   * Remove member from channel.
   */
  removeMember(channelId: ChannelId, entityId: EntityId): void {
    const stmt = this.db.prepare(`
      DELETE FROM channel_members WHERE channel_id = ? AND entity_id = ?
    `);

    stmt.run(channelId, entityId);
  }

  /**
   * Get all members of a channel.
   */
  getMembers(channelId: ChannelId): ChannelMember[] {
    const stmt = this.db.prepare(`
      SELECT * FROM channel_members WHERE channel_id = ?
    `);

    return stmt.all(channelId) as ChannelMember[];
  }

  /**
   * Check if entity is a member of channel.
   */
  isMember(channelId: ChannelId, entityId: EntityId): boolean {
    const stmt = this.db.prepare(`
      SELECT 1 FROM channel_members WHERE channel_id = ? AND entity_id = ?
    `);

    return stmt.get(channelId, entityId) !== null;
  }

  /**
   * Get member's role in channel.
   */
  getMemberRole(channelId: ChannelId, entityId: EntityId): ChannelMemberRole | null {
    const stmt = this.db.prepare(`
      SELECT role FROM channel_members WHERE channel_id = ? AND entity_id = ?
    `);

    const result = stmt.get(channelId, entityId) as { role: ChannelMemberRole } | null;
    return result?.role ?? null;
  }

  /**
   * Update member's role.
   */
  updateMemberRole(channelId: ChannelId, entityId: EntityId, role: ChannelMemberRole): void {
    const stmt = this.db.prepare(`
      UPDATE channel_members SET role = ? WHERE channel_id = ? AND entity_id = ?
    `);

    stmt.run(role, channelId, entityId);
  }

  // --------------------------------------------------------------------------
  // Delete
  // --------------------------------------------------------------------------

  /**
   * Delete a channel and all its members.
   */
  delete(id: ChannelId): void {
    const stmt = this.db.prepare(`
      DELETE FROM channels WHERE id = ?
    `);

    stmt.run(id);
  }

  // --------------------------------------------------------------------------
  // Moderation
  // --------------------------------------------------------------------------

  /**
   * Kick an entity from a channel (remove member, can rejoin).
   * Channel moderation is kick + set-role; cross-account blocking is handled
   * by the account permission matrix (channel_bans was retired in schema v3).
   */
  kick(channelId: ChannelId, entityId: EntityId): void {
    this.removeMember(channelId, entityId);
  }

  // --------------------------------------------------------------------------
  // Helpers
  // --------------------------------------------------------------------------

  private mapRowToChannel(row: any): Channel {
    return {
      id: row.id,
      name: row.name,
      created_by_entity: row.created_by_entity,
      is_public: row.is_public === 1,
      created_at: row.created_at,
    };
  }
}
