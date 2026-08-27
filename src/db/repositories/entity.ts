// Entity Repository - CRUD Operations for Entities

import { Database } from 'bun:sqlite';
import type { Entity, EntityId, AccountId, EntityType, EntityCapabilities } from '../../types';

// ============================================================================
// Entity Repository
// ============================================================================

export class EntityRepository {
  constructor(private db: Database) {}

  // --------------------------------------------------------------------------
  // Create
  // --------------------------------------------------------------------------

  /**
   * Create a new entity.
   */
  create(
    id: EntityId,
    accountId: AccountId,
    type: EntityType,
    publicKey: string,
    displayName?: string,
    capabilities?: Partial<EntityCapabilities>
  ): Entity {
    const defaultCapabilities: EntityCapabilities = {
      can_send: true,
      can_join_channel: true,
      can_create_entities: false,
      can_create_channels: false,
      can_manage_entities: false,
      encrypt_messages: false,
    };

    const finalCapabilities = {
      ...defaultCapabilities,
      ...capabilities,
    };

    const stmt = this.db.prepare(`
      INSERT INTO entities (id, account_id, type, display_name, capabilities, public_key)
      VALUES (?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      accountId,
      type,
      displayName ?? null,
      JSON.stringify(finalCapabilities),
      publicKey
    );

    return this.getById(id)!;
  }

  // --------------------------------------------------------------------------
  // Read
  // --------------------------------------------------------------------------

  /**
   * Get entity by ID.
   */
  getById(id: EntityId): Entity | null {
    const stmt = this.db.prepare(`
      SELECT * FROM entities WHERE id = ?
    `);

    const row = stmt.get(id) as any;
    if (!row) return null;

    return this.mapRowToEntity(row);
  }

  /**
   * Get all entities for an account.
   */
  getByAccountId(accountId: AccountId): Entity[] {
    const stmt = this.db.prepare(`
      SELECT * FROM entities WHERE account_id = ?
    `);

    const rows = stmt.all(accountId) as any[];
    return rows.map(this.mapRowToEntity);
  }

  /**
   * Get all entities.
   */
  getAll(): Entity[] {
    const stmt = this.db.prepare(`
      SELECT * FROM entities
    `);

    const rows = stmt.all() as any[];
    return rows.map(this.mapRowToEntity);
  }

  /**
   * Get the directory for an account: the account's own entities plus
   * entities other accounts have actively granted to it. This is the
   * visibility set for scope:'directory' — cross-account discovery is
   * default-deny, so granted entities are the only foreign ones visible.
   */
  getDirectoryForAccount(accountId: AccountId): Entity[] {
    const stmt = this.db.prepare(`
      SELECT e.* FROM entities e
      WHERE e.account_id = ?
      UNION
      SELECT e.* FROM entities e
      JOIN grants g ON g.entity_id = e.id
      WHERE g.grantee_account_id = ?
      AND g.status = 'active'
      AND (g.expires_at IS NULL OR datetime(g.expires_at) > datetime('now'))
    `);

    const rows = stmt.all(accountId, accountId) as any[];
    return rows.map(this.mapRowToEntity);
  }

  /**
   * Get all online entities.
   */
  getOnline(): Entity[] {
    const stmt = this.db.prepare(`
      SELECT * FROM entities WHERE status = 'online'
    `);

    const rows = stmt.all() as any[];
    return rows.map(this.mapRowToEntity);
  }

  /**
   * Get entities in a channel.
   */
  getByChannelId(channelId: string): Entity[] {
    const stmt = this.db.prepare(`
      SELECT e.* FROM entities e
      JOIN channel_members cm ON e.id = cm.entity_id
      WHERE cm.channel_id = ?
    `);

    const rows = stmt.all(channelId) as any[];
    return rows.map(this.mapRowToEntity);
  }

  // --------------------------------------------------------------------------
  // Update
  // --------------------------------------------------------------------------

  /**
   * Update entity status (connection-derived: online/offline/away).
   */
  updateStatus(id: EntityId, status: 'online' | 'offline' | 'away'): void {
    const stmt = this.db.prepare(`
      UPDATE entities
      SET status = ?, last_seen = datetime('now')
      WHERE id = ?
    `);

    stmt.run(status, id);
  }

  /**
   * Update entity availability (user intent: available/unavailable).
   * Independent of connection status; persists across reconnects.
   */
  updateAvailability(id: EntityId, availability: 'available' | 'unavailable'): void {
    // Stamps last_state_change only when the value actually differs — the
    // column is named for a CHANGE, and re-declaring the same value is not
    // one. If a repeat refreshed it, an agent looping on one state would look
    // perpetually fresh, which is the failure this column exists to avoid.
    const stmt = this.db.prepare(`
      UPDATE entities
      SET availability = ?,
          last_state_change = CASE WHEN availability IS ?
                                   THEN last_state_change
                                   ELSE datetime('now') END
      WHERE id = ?
    `);

    stmt.run(availability, availability, id);
  }

  /**
   * Declare whether this entity's work queue is empty.
   *
   * DECLARED state — only the entity knows, and nothing external can derive it.
   * `null` means never declared, which is deliberately distinct from a declared
   * false: an entity that has never spoken has made no claim, and treating that
   * as "busy" would invent one.
   *
   * READ IT WITH ITS NEIGHBOURS. `queue_empty = 0` alone means working OR dead,
   * and the two are not separable from that column:
   *
   *   queue_empty=0, last_state_change fresh                 -> working, changing
   *   queue_empty=0, last_state_change old, heartbeat fresh  -> one long task
   *   queue_empty=0, last_state_change old, heartbeat stale  -> died mid-task
   *
   * The last two are the pair that matters and the ONLY thing separating them
   * is the heartbeat — so this is a triple, not a pair. A reader who consults
   * queue_empty on its own will call a dead agent busy.
   */
  updateQueueEmpty(id: EntityId, queueEmpty: boolean): void {
    const value = queueEmpty ? 1 : 0;
    const stmt = this.db.prepare(`
      UPDATE entities
      SET queue_empty = ?,
          last_state_change = CASE WHEN queue_empty IS ?
                                   THEN last_state_change
                                   ELSE datetime('now') END
      WHERE id = ?
    `);

    stmt.run(value, value, id);
  }

  /**
   * Update entity display name.
   */
  updateDisplayName(id: EntityId, displayName: string): void {
    const stmt = this.db.prepare(`
      UPDATE entities
      SET display_name = ?
      WHERE id = ?
    `);

    stmt.run(displayName, id);
  }

  /**
   * Update entity capabilities.
   */
  updateCapabilities(id: EntityId, capabilities: Partial<EntityCapabilities>): void {
    const current = this.getById(id);
    if (!current) return;

    const updated = {
      ...current.capabilities,
      ...capabilities,
    };

    const stmt = this.db.prepare(`
      UPDATE entities
      SET capabilities = ?
      WHERE id = ?
    `);

    stmt.run(JSON.stringify(updated), id);
  }

  /**
   * Update entity location (for federation).
   */
  updateLocation(id: EntityId, locationServer: string | null): void {
    const stmt = this.db.prepare(`
      UPDATE entities
      SET location_server = ?
      WHERE id = ?
    `);

    stmt.run(locationServer, id);
  }

  // --------------------------------------------------------------------------
  // Delete
  // --------------------------------------------------------------------------

  /**
   * Delete an entity.
   */
  delete(id: EntityId): void {
    const stmt = this.db.prepare(`
      DELETE FROM entities WHERE id = ?
    `);

    stmt.run(id);
  }

  /**
   * Delete all entities for an account.
   */
  deleteByAccountId(accountId: AccountId): void {
    const stmt = this.db.prepare(`
      DELETE FROM entities WHERE account_id = ?
    `);

    stmt.run(accountId);
  }

  // --------------------------------------------------------------------------
  // Helpers
  // --------------------------------------------------------------------------

  private mapRowToEntity(row: any): Entity {
    return {
      id: row.id,
      account_id: row.account_id,
      type: row.type,
      display_name: row.display_name,
      capabilities: JSON.parse(row.capabilities || '{}'),
      location_server: row.location_server,
      public_key: row.public_key,
      status: row.status || 'offline',
      availability: row.availability || 'available',
      // NULL is preserved as null, not coerced to false. "never declared" and
      // "declared not-empty" are different claims, and this mapper is the one
      // place every reader passes through — `!!row.queue_empty` here would
      // erase the distinction for all of them at once.
      queue_empty:
        row.queue_empty === null || row.queue_empty === undefined
          ? null
          : Boolean(row.queue_empty),
      last_state_change: row.last_state_change ?? null,
      created_at: row.created_at,
      last_seen: row.last_seen,
    };
  }
}
