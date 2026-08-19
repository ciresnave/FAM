// Grant Repository - Cross-Account Access Grants
//
// A grant gives the grantee account permission to message a specific entity
// owned by the grantor account. Cross-account DMs are default-deny; an
// active (non-revoked, non-expired) grant is required.

import { Database } from 'bun:sqlite';
import { randomUUID } from 'crypto';
import type { Grant, AccountId, EntityId, GrantCapabilities } from '../../types';

// ============================================================================
// Grant Repository
// ============================================================================

export class GrantRepository {
  constructor(private db: Database) {}

  // --------------------------------------------------------------------------
  // Create
  // --------------------------------------------------------------------------

  /**
   * Create a grant. Throws (SQLite UNIQUE violation) if an identical
   * grantor/grantee/entity grant already exists regardless of status —
   * callers should check findActive/findAny first and surface a 409.
   */
  create(
    grantorAccountId: AccountId,
    granteeAccountId: AccountId,
    entityId: EntityId,
    capabilities?: GrantCapabilities,
    expiresAt?: string | null
  ): Grant {
    const id = randomUUID();
    const stmt = this.db.prepare(`
      INSERT INTO grants (id, grantor_account_id, grantee_account_id, entity_id, capabilities, expires_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      grantorAccountId,
      granteeAccountId,
      entityId,
      JSON.stringify(capabilities ?? {}),
      expiresAt ?? null
    );

    return this.getById(id)!;
  }

  // --------------------------------------------------------------------------
  // Read
  // --------------------------------------------------------------------------

  getById(id: string): Grant | null {
    const stmt = this.db.prepare('SELECT * FROM grants WHERE id = ?');
    return this.mapRow(stmt.get(id));
  }

  /**
   * Find the active grant for (grantor, grantee, entity).
   * Active = status 'active' and not expired.
   * NOTE: datetime(expires_at) normalizes ISO-8601 strings (with 'T'/'Z')
   * for comparison against SQLite's datetime('now') format.
   */
  findActive(grantorAccountId: AccountId, granteeAccountId: AccountId, entityId: EntityId): Grant | null {
    const stmt = this.db.prepare(`
      SELECT * FROM grants
      WHERE grantor_account_id = ? AND grantee_account_id = ? AND entity_id = ?
      AND status = 'active'
      AND (expires_at IS NULL OR datetime(expires_at) > datetime('now'))
      LIMIT 1
    `);
    return this.mapRow(stmt.get(grantorAccountId, granteeAccountId, entityId));
  }

  /**
   * Find any grant (any status) for the tuple — used for 409 conflict checks.
   */
  findAny(grantorAccountId: AccountId, granteeAccountId: AccountId, entityId: EntityId): Grant | null {
    const stmt = this.db.prepare(`
      SELECT * FROM grants
      WHERE grantor_account_id = ? AND grantee_account_id = ? AND entity_id = ?
      LIMIT 1
    `);
    return this.mapRow(stmt.get(grantorAccountId, granteeAccountId, entityId));
  }

  listByGrantor(accountId: AccountId): Grant[] {
    const stmt = this.db.prepare('SELECT * FROM grants WHERE grantor_account_id = ? ORDER BY created_at DESC');
    return (stmt.all(accountId) as any[]).map(r => this.mapRow(r)!);
  }

  listByGrantee(accountId: AccountId): Grant[] {
    const stmt = this.db.prepare('SELECT * FROM grants WHERE grantee_account_id = ? ORDER BY created_at DESC');
    return (stmt.all(accountId) as any[]).map(r => this.mapRow(r)!);
  }

  // --------------------------------------------------------------------------
  // Update
  // --------------------------------------------------------------------------

  /**
   * Revoke a grant. Idempotent; returns true if a row was affected.
   */
  revoke(id: string): boolean {
    const stmt = this.db.prepare(`
      UPDATE grants SET status = 'revoked', revoked_at = datetime('now')
      WHERE id = ? AND status = 'active'
    `);
    return stmt.run(id).changes > 0;
  }

  // --------------------------------------------------------------------------
  // Cleanup
  // --------------------------------------------------------------------------

  /**
   * Mark expired active grants as revoked. Called by the periodic cleanup job.
   */
  revokeExpired(): number {
    const stmt = this.db.prepare(`
      UPDATE grants SET status = 'revoked', revoked_at = datetime('now')
      WHERE status = 'active' AND expires_at IS NOT NULL AND datetime(expires_at) <= datetime('now')
    `);
    return stmt.run().changes;
  }

  // --------------------------------------------------------------------------
  // Helpers
  // --------------------------------------------------------------------------

  private mapRow(row: any): Grant | null {
    if (!row) return null;
    return {
      id: row.id,
      grantor_account_id: row.grantor_account_id,
      grantee_account_id: row.grantee_account_id,
      entity_id: row.entity_id,
      capabilities: JSON.parse(row.capabilities || '{}'),
      status: row.status,
      created_at: row.created_at,
      expires_at: row.expires_at,
      revoked_at: row.revoked_at,
    };
  }
}
