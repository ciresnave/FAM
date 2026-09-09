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
  /**
   * The instance that authenticated this session, or null when the client did
   * not claim the identity.
   *
   * ⚠️ NULL IS A REAL STATE, NOT A ROW WAITING TO BE FILLED IN. A null-instance
   * session belongs to a client that has not opted in to claiming and is never
   * superseded — which is how the `type='human'` policy stays undecided rather
   * than being answered by a default.
   */
  instance_id: string | null;
  /**
   * When another instance took this identity, or null while this session is
   * live.
   *
   * \u26a0\ufe0f MARKED RATHER THAN DELETED, so the refusal can name its cause. A
   * deleted session is indistinguishable from an expired one, a mistyped id,
   * and one that never existed \u2014 and the holder is told "Invalid session" and
   * sent to check credentials that were never wrong.
   */
  superseded_at: string | null;
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
  create(entityId: EntityId, websocketId?: string, instanceId?: string): Session {
    const id = randomUUID();

    const stmt = this.db.prepare(`
      INSERT INTO sessions (id, entity_id, websocket_id, instance_id)
      VALUES (?, ?, ?, ?)
    `);

    stmt.run(id, entityId, websocketId ?? null, instanceId ?? null);

    return this.getById(id)!;
  }

  /**
   * Mark this entity's sessions that belong to a DIFFERENT instance as
   * superseded, and return how many were marked.
   *
   * ⚠️ SCOPED THREE WAYS, AND EACH ONE MATTERS.
   *
   * By ENTITY, because a claim on one identity must not touch another's — a
   * too-wide DELETE here would evict the whole account and still pass every
   * test about the claiming entity.
   *
   * By INSTANCE, because a second CONNECTION from the same process is not a
   * claim. Multi-connection is a designed feature (`websocket.ts` keeps
   * `entityId -> Set<sessionId>`), so a mechanism that reduced to "one session
   * per entity" would break something that works to fix something else.
   *
   * And by NOT-NULL, because a session that never claimed the identity is not a
   * rival for it. Superseding opted-out sessions would make the opt-out
   * meaningless and would silently decide the `type='human'` question.
   *
   * ⚠️ BUT THE `instance_id IS NOT NULL` CLAUSE IS NOT WHAT ENFORCES THAT, AND
   * SAYING SO IS THE POINT. Measured: deleting it changes nothing — 10 pass, 0
   * fail — because `NULL != 'x'` evaluates to NULL, not TRUE, so SQL's
   * three-valued logic already excludes opted-out rows from `instance_id != ?`.
   * The clause is REDUNDANT.
   *
   * It is kept as an explicit statement of intent, not as an active filter,
   * because the protection is currently a PROPERTY OF THE COMPARISON rather
   * than of anything written down: rewriting `instance_id != ?` as
   * `COALESCE(instance_id, '') != ?` silently sweeps every opted-out session.
   * Measured too — that mutation reddens exactly one test, "a non-claiming
   * authentication is not itself superseded by a later claim".
   *
   * So the property is real and guarded; the guard is the TEST, and this clause
   * is a comment that happens to be executable. A guard whose justification is
   * wrong is one the next reader trusts for the wrong reason.
   */
  supersedeOtherInstances(entityId: EntityId, instanceId: string): number {
    const where = `entity_id = ?
       AND instance_id IS NOT NULL
       AND instance_id != ?
       AND superseded_at IS NULL`;

    const rows = this.db
      .prepare(`SELECT id FROM sessions WHERE ${where}`)
      .all(entityId, instanceId) as Array<{ id: string }>;

    if (rows.length === 0) return 0;

    // ⚠️ MARKED, NOT DELETED. The row is what lets the next request answer
    // "another instance took this identity" instead of "Invalid session".
    this.db
      .prepare(`UPDATE sessions SET superseded_at = datetime('now') WHERE ${where}`)
      .run(entityId, instanceId);

    return rows.length;
  }

  // --------------------------------------------------------------------------
  // Read
  // --------------------------------------------------------------------------

  /**
   * Get session by ID.
   */
  /**
   * A LIVE session by id. Superseded sessions are excluded.
   *
   * \u26a0\ufe0f FAIL-CLOSED BY DEFAULT, DELIBERATELY. Every existing caller \u2014 the
   * session middleware, the WebSocket upgrade \u2014 gets the safe answer with no
   * change. The diagnostic lookup that CAN see a superseded row is a separate,
   * explicitly-named method, so nothing treats a dead session as live by
   * forgetting to filter.
   */
  getById(id: string): Session | null {
    const stmt = this.db.prepare(`
      SELECT * FROM sessions WHERE id = ? AND superseded_at IS NULL
    `);

    return stmt.get(id) as Session | null;
  }

  /**
   * A session by id ONLY IF it was superseded — the diagnostic lookup.
   *
   * ⚠️ THIS EXISTS SO A REFUSAL CAN NAME ITS CAUSE. Without it a superseded
   * holder is told "Invalid session", which is what an expired session, a
   * mistyped id, and a forged one all say — so the one message points at
   * credentials, which were never the problem.
   *
   * Deliberately separate from `getById` rather than a flag on it: a boolean
   * parameter would let a caller ask for a dead session by accident, and every
   * caller that forgot the argument would get the safe answer only by luck.
   */
  getSupersededById(id: string): Session | null {
    const stmt = this.db.prepare(`
      SELECT * FROM sessions WHERE id = ? AND superseded_at IS NOT NULL
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
