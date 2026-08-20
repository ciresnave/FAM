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
  create(
    id: AccountId,
    displayName?: string,
    provider?: string,
    providerAccountId?: string
  ): Account {
    const stmt = this.db.prepare(`
      INSERT INTO accounts (id, display_name, provider, provider_account_id)
      VALUES (?, ?, ?, ?)
    `);

    stmt.run(id, displayName ?? null, provider ?? null, providerAccountId ?? null);

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

  /**
   * Look an account up by the provider's own stable user id.
   *
   * This — not the email — is the authoritative identity. The provider id
   * cannot be chosen by the user, whereas an email address can be typed into a
   * profile field. Resolving by it also means a user changing their email at
   * the provider keeps the same FAM account.
   */
  getByProviderIdentity(provider: string, providerAccountId: string): Account | null {
    const stmt = this.db.prepare(`
      SELECT * FROM accounts WHERE provider = ? AND provider_account_id = ?
    `);

    return stmt.get(provider, providerAccountId) as Account | null;
  }

  /**
   * Bind an unbound (pre-v6) account to a provider identity on first login.
   */
  bindProvider(id: AccountId, provider: string, providerAccountId: string): void {
    const stmt = this.db.prepare(`
      UPDATE accounts
      SET provider = ?, provider_account_id = ?, updated_at = datetime('now')
      WHERE id = ? AND provider IS NULL
    `);

    stmt.run(provider, providerAccountId, id);
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
