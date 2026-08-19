// Invitation Repository - CRUD Operations for Channel Invitations

import { Database } from 'bun:sqlite';
import { randomUUID } from 'crypto';
import type { ChannelId, EntityId } from '../../types';

// ============================================================================
// Types
// ============================================================================

export interface ChannelInvitation {
  id: string;
  channel_id: ChannelId;
  invited_by: EntityId;
  invited_entity: EntityId;
  status: 'pending' | 'accepted' | 'declined' | 'expired';
  created_at: string;
  expires_at: string | null;
}

// ============================================================================
// Invitation Repository
// ============================================================================

export class InvitationRepository {
  constructor(private db: Database) {}

  /**
   * Create a new channel invitation.
   */
  create(
    channelId: ChannelId,
    invitedBy: EntityId,
    invitedEntity: EntityId,
    expiresInDays: number = 7
  ): ChannelInvitation {
    const id = randomUUID();
    const expiresAt = new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000).toISOString();

    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO channel_invitations (id, channel_id, invited_by, invited_entity, expires_at)
      VALUES (?, ?, ?, ?, ?)
    `);

    stmt.run(id, channelId, invitedBy, invitedEntity, expiresAt);

    return this.getById(id)!;
  }

  /**
   * Get invitation by ID.
   */
  getById(id: string): ChannelInvitation | null {
    const stmt = this.db.prepare(`
      SELECT * FROM channel_invitations WHERE id = ?
    `);

    return stmt.get(id) as ChannelInvitation | null;
  }

  /**
   * Get pending invitations for an entity.
   * NOTE: datetime(expires_at) normalizes ISO-8601 strings (with 'T'/'Z')
   * for comparison against SQLite's datetime('now') format.
   */
  getPendingForEntity(entityId: EntityId): ChannelInvitation[] {
    const stmt = this.db.prepare(`
      SELECT * FROM channel_invitations
      WHERE invited_entity = ? AND status = 'pending'
      AND (expires_at IS NULL OR datetime(expires_at) > datetime('now'))
      ORDER BY created_at DESC
    `);

    return stmt.all(entityId) as ChannelInvitation[];
  }

  /**
   * Get invitations sent by an entity for a channel.
   */
  getByChannel(channelId: ChannelId): ChannelInvitation[] {
    const stmt = this.db.prepare(`
      SELECT * FROM channel_invitations
      WHERE channel_id = ?
      ORDER BY created_at DESC
    `);

    return stmt.all(channelId) as ChannelInvitation[];
  }

  /**
   * Accept an invitation.
   */
  accept(id: string): void {
    const stmt = this.db.prepare(`
      UPDATE channel_invitations SET status = 'accepted' WHERE id = ? AND status = 'pending'
    `);

    stmt.run(id);
  }

  /**
   * Decline an invitation.
   */
  decline(id: string): void {
    const stmt = this.db.prepare(`
      UPDATE channel_invitations SET status = 'declined' WHERE id = ? AND status = 'pending'
    `);

    stmt.run(id);
  }

  /**
   * Revoke an invitation.
   */
  revoke(id: string): void {
    const stmt = this.db.prepare(`
      DELETE FROM channel_invitations WHERE id = ?
    `);

    stmt.run(id);
  }

  /**
   * Check if there's a pending invitation for an entity in a channel.
   */
  hasPending(channelId: ChannelId, entityId: EntityId): boolean {
    const stmt = this.db.prepare(`
      SELECT 1 FROM channel_invitations
      WHERE channel_id = ? AND invited_entity = ? AND status = 'pending'
      AND (expires_at IS NULL OR datetime(expires_at) > datetime('now'))
    `);

    return stmt.get(channelId, entityId) !== null;
  }
}
