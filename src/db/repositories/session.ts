// Session Repository - CRUD Operations for Active Sessions

import { Database } from 'bun:sqlite';
import { randomUUID } from 'crypto';
import type { EntityId } from '../../types';

// ============================================================================
// Session Types
// ============================================================================

export interface Session {
  id: string;
  entity_id: EntityId;
  connected_at: string;
  last_heartbeat: string;
  websocket_id: string | null;
}

// ============================================================================
// Session Repository
// ============================================================================

export class SessionRepository {
  constructor(private db: Database) {}

  // --------------------------------------------------------------------------
  // Create
  // --------------------------------------------------------------------------

  /**
   * Create a new session for an entity.
   */
  create(entityId: EntityId, websocketId?: string): Session {
    const id = randomUUID();

    const stmt = this.db.prepare(`
      INSERT INTO sessions (id, entity_id, websocket_id)
      VALUES (?, ?, ?)
    `);

    stmt.run(id, entityId, websocketId ?? null);

    return this.getById(id)!;
  }

  // --------------------------------------------------------------------------
  // Read
  // --------------------------------------------------------------------------

  /**
   * Get session by ID.
   */
  getById(id: string): Session | null {
    const stmt = this.db.prepare(`
      SELECT * FROM sessions WHERE id = ?
    `);

    return stmt.get(id) as Session | null;
  }

  /**
   * Get active session for an entity.
   */
  getByEntityId(entityId: EntityId): Session | null {
    const stmt = this.db.prepare(`
      SELECT * FROM sessions
      WHERE entity_id = ?
      AND last_heartbeat > datetime('now', '-60 seconds')
    `);

    return stmt.get(entityId) as Session | null;
  }

  /**
   * Count all sessions for an entity (regardless of heartbeat).
   */
  getCountByEntityId(entityId: EntityId): number {
    const stmt = this.db.prepare(`
      SELECT COUNT(*) as count FROM sessions WHERE entity_id = ?
    `);

    const result = stmt.get(entityId) as { count: number };
    return result.count;
  }

  /**
   * Get all active sessions.
   */
  getActive(): Session[] {
    const stmt = this.db.prepare(`
      SELECT * FROM sessions
      WHERE last_heartbeat > datetime('now', '-60 seconds')
    `);

    return stmt.all() as Session[];
  }

  /**
   * Check if entity has an active session.
   */
  isActive(entityId: EntityId): boolean {
    const stmt = this.db.prepare(`
      SELECT 1 FROM sessions
      WHERE entity_id = ? AND last_heartbeat > datetime('now', '-60 seconds')
    `);

    return stmt.get(entityId) !== null;
  }

  // --------------------------------------------------------------------------
  // Update
  // --------------------------------------------------------------------------

  /**
   * Update heartbeat timestamp.
   */
  updateHeartbeat(id: string): void {
    const stmt = this.db.prepare(`
      UPDATE sessions SET last_heartbeat = datetime('now')
      WHERE id = ?
    `);

    stmt.run(id);
  }

  /**
   * Update websocket ID.
   */
  updateWebsocketId(id: string, websocketId: string): void {
    const stmt = this.db.prepare(`
      UPDATE sessions SET websocket_id = ?
      WHERE id = ?
    `);

    stmt.run(websocketId, id);
  }

  // --------------------------------------------------------------------------
  // Delete
  // --------------------------------------------------------------------------

  /**
   * End a session.
   */
  delete(id: string): void {
    const stmt = this.db.prepare(`
      DELETE FROM sessions WHERE id = ?
    `);

    stmt.run(id);
  }

  /**
   * End all sessions for an entity.
   */
  deleteByEntityId(entityId: EntityId): void {
    const stmt = this.db.prepare(`
      DELETE FROM sessions WHERE entity_id = ?
    `);

    stmt.run(entityId);
  }

  /**
   * Clean up stale sessions (no heartbeat in 60 seconds).
   */
  cleanupStale(): number {
    const stmt = this.db.prepare(`
      DELETE FROM sessions
      WHERE last_heartbeat < datetime('now', '-60 seconds')
    `);

    const result = stmt.run();
    return result.changes;
  }

  // --------------------------------------------------------------------------
  // Stats
  // --------------------------------------------------------------------------

  /**
   * Get active session count.
   */
  getActiveCount(): number {
    const stmt = this.db.prepare(`
      SELECT COUNT(*) as count FROM sessions
      WHERE last_heartbeat > datetime('now', '-60 seconds')
    `);

    const result = stmt.get() as { count: number };
    return result.count;
  }
}
