// Permission Rule Repository - Per-Account Allow/Deny Matrix
//
// Rules live on the TARGET's account: they protect that account's entities
// (a specific entity or all of them) from a source (a specific entity or an
// entire account). Deny rules revoke; allow rules override broader denies.

import { Database } from 'bun:sqlite';
import { randomUUID } from 'crypto';
import type {
  PermissionRule,
  AccountId,
  EntityId,
  PermissionTargetType,
  PermissionSourceType,
  PermissionAction,
} from '../../types';

// ============================================================================
// Permission Rule Repository
// ============================================================================

export interface CreatePermissionRule {
  account_id: AccountId;
  target_type: PermissionTargetType;
  target_entity_id?: EntityId | null;
  source_type: PermissionSourceType;
  source_entity_id?: EntityId | null;
  source_account_id?: AccountId | null;
  action: PermissionAction;
  created_by_entity?: EntityId | null;
}

export class PermissionRepository {
  constructor(private db: Database) {}

  // --------------------------------------------------------------------------
  // Create
  // --------------------------------------------------------------------------

  create(rule: CreatePermissionRule): PermissionRule {
    // Conflict check: identical tuple must not already exist
    if (this.findIdentical(rule)) {
      throw new Error('conflict'); // callers translate to ConflictError
    }

    const id = randomUUID();
    const stmt = this.db.prepare(`
      INSERT INTO permissions (id, account_id, target_type, target_entity_id, source_type, source_entity_id, source_account_id, action, created_by_entity)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      rule.account_id,
      rule.target_type,
      rule.target_entity_id ?? null,
      rule.source_type,
      rule.source_entity_id ?? null,
      rule.source_account_id ?? null,
      rule.action,
      rule.created_by_entity ?? null
    );

    return this.getById(id)!;
  }

  // --------------------------------------------------------------------------
  // Read
  // --------------------------------------------------------------------------

  getById(id: string): PermissionRule | null {
    const stmt = this.db.prepare('SELECT * FROM permissions WHERE id = ?');
    return (stmt.get(id) as any) ?? null;
  }

  /**
   * All rules belonging to an account (the account whose entities are protected).
   */
  listByAccount(accountId: AccountId): PermissionRule[] {
    const stmt = this.db.prepare('SELECT * FROM permissions WHERE account_id = ? ORDER BY created_at DESC');
    return stmt.all(accountId) as any[];
  }

  // --------------------------------------------------------------------------
  // Delete
  // --------------------------------------------------------------------------

  /**
   * Delete a rule owned by an account. Returns true if a row was removed.
   */
  deleteForAccount(id: string, accountId: AccountId): boolean {
    const stmt = this.db.prepare('DELETE FROM permissions WHERE id = ? AND account_id = ?');
    return stmt.run(id, accountId).changes > 0;
  }

  // --------------------------------------------------------------------------
  // Helpers
  // --------------------------------------------------------------------------

  private findIdentical(rule: CreatePermissionRule): boolean {
    // Identity excludes `action`: a tuple with both allow and deny would be
    // ambiguous at equal specificity, so any existing rule for the tuple
    // blocks creating another.
    const stmt = this.db.prepare(`
      SELECT 1 FROM permissions
      WHERE account_id = ?
      AND target_type = ?
      AND target_entity_id IS ?
      AND source_type = ?
      AND source_entity_id IS ?
      AND source_account_id IS ?
    `);
    return stmt.get(
      rule.account_id,
      rule.target_type,
      rule.target_entity_id ?? null,
      rule.source_type,
      rule.source_entity_id ?? null,
      rule.source_account_id ?? null
    ) !== null;
  }
}
