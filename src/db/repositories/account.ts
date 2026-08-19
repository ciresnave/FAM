// Account Repository - CRUD Operations for Accounts

import { Database } from 'bun:sqlite';
import type { Account, AccountId } from '../../types';

// ============================================================================
// Account Repository
// ============================================================================

export class AccountRepository {
  constructor(private db: Database) {}

  // --------------------------------------------------------------------------
  // Create
  // --------------------------------------------------------------------------

  /**
   * Create a new account.
   */
  create(id: AccountId, displayName?: string): Account {
    const stmt = this.db.prepare(`
      INSERT INTO accounts (id, display_name)
      VALUES (?, ?)
    `);
    
    stmt.run(id, displayName ?? null);
    
    return this.getById(id)!;
  }

  // --------------------------------------------------------------------------
  // Read
  // --------------------------------------------------------------------------

  /**
   * Get account by ID (email).
   */
  getById(id: AccountId): Account | null {
    const stmt = this.db.prepare(`
      SELECT * FROM accounts WHERE id = ?
    `);
    
    return stmt.get(id) as Account | null;
  }

  /**
   * Check if account exists.
   */
  exists(id: AccountId): boolean {
    return this.getById(id) !== null;
  }

  // --------------------------------------------------------------------------
  // Update
  // --------------------------------------------------------------------------

  /**
   * Update account display name.
   */
  updateDisplayName(id: AccountId, displayName: string): void {
    const stmt = this.db.prepare(`
      UPDATE accounts
      SET display_name = ?, updated_at = datetime('now')
      WHERE id = ?
    `);
    
    stmt.run(displayName, id);
  }

  // --------------------------------------------------------------------------
  // Delete
  // --------------------------------------------------------------------------

  /**
   * Delete an account and all associated data (cascades).
   */
  delete(id: AccountId): void {
    const stmt = this.db.prepare(`
      DELETE FROM accounts WHERE id = ?
    `);
    
    stmt.run(id);
  }
}
