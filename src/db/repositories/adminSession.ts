// Admin Session Repository — browser sessions for the admin console.
//
// Distinct from SessionRepository, which authenticates ENTITIES via Ed25519
// challenge-response. This authenticates a human account holder in a browser.
// The difference that matters: browsers attach cookies automatically, so a
// session identified by a cookie is reachable by any page the user visits.
// That is why every row carries a csrf_token.

import { Database } from 'bun:sqlite';
import { randomUUID } from 'crypto';
import type { AccountId } from '../../types';

export interface AdminSession {
  id: string;
  account_id: AccountId;
  csrf_token: string;
  created_at: string;
  expires_at: string;
}

/** How long a browser session lasts without re-authenticating. */
export const ADMIN_SESSION_TTL_HOURS = 12;

export class AdminSessionRepository {
  constructor(private db: Database) {}

  /**
   * Open a browser session. Both the session id and the CSRF token are
   * independently random: the CSRF token must not be derivable from the
   * cookie, or an attacker who can guess one has both.
   */
  create(accountId: AccountId, ttlHours: number = ADMIN_SESSION_TTL_HOURS): AdminSession {
    const id = randomUUID();
    const csrfToken = randomUUID();

    this.db
      .prepare(
        `INSERT INTO admin_sessions (id, account_id, csrf_token, expires_at)
         VALUES (?, ?, ?, datetime('now', ?))`
      )
      // Sign belongs to the number, not the template: "+-1 hours" is not a
      // valid SQLite modifier and yields NULL, which then trips the NOT NULL
      // constraint rather than producing an expired row. Negative TTLs are used
      // by tests to construct an already-expired session.
      .run(id, accountId, csrfToken, `${ttlHours >= 0 ? '+' : ''}${ttlHours} hours`);

    return this.getById(id)!;
  }

  getById(id: string): AdminSession | null {
    return (
      (this.db
        .prepare('SELECT * FROM admin_sessions WHERE id = ?')
        .get(id) as AdminSession | null) ?? null
    );
  }

  /**
   * Fetch only if unexpired. Expiry is compared with julianday() on both sides
   * — `expires_at` is written by SQLite's datetime() so the shapes match today,
   * but a string comparison would silently skip the boundary if either side
   * ever became ISO-8601. Same defect already found twice in this repo.
   */
  getActive(id: string): AdminSession | null {
    return (
      (this.db
        .prepare(
          `SELECT * FROM admin_sessions
           WHERE id = ? AND julianday(expires_at) > julianday('now')`
        )
        .get(id) as AdminSession | null) ?? null
    );
  }

  delete(id: string): void {
    this.db.prepare('DELETE FROM admin_sessions WHERE id = ?').run(id);
  }

  deleteForAccount(accountId: AccountId): void {
    this.db.prepare('DELETE FROM admin_sessions WHERE account_id = ?').run(accountId);
  }

  /** Remove expired rows. Safe to call on any schedule. */
  cleanupExpired(): number {
    return this.db
      .prepare(`DELETE FROM admin_sessions WHERE julianday(expires_at) <= julianday('now')`)
      .run().changes;
  }
}
