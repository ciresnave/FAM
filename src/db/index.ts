// Database Connection and Main Export

import { Database } from 'bun:sqlite';
import { homedir } from 'os';
import { join } from 'path';
import { initializeDatabase } from './schema';
import { createContext } from './transaction';
import type { DatabaseContext } from './transaction';

// ============================================================================
// Constants
// ============================================================================

const DEFAULT_DB_NAME = '.fam.db';

// ============================================================================
// Database Connection
// ============================================================================

let dbContext: DatabaseContext | null = null;

/**
 * Resolve database path, expanding ~ to home directory.
 */
function resolveDbPath(dbPath?: string): string {
  const path = dbPath || process.env.FAM_DB_PATH || join(homedir(), DEFAULT_DB_NAME);
  
  // Expand ~ if present
  if (path.startsWith('~')) {
    return join(homedir(), path.slice(1));
  }
  
  return path;
}

/**
 * Get or create the database context.
 */
export function getDatabaseContext(dbPath?: string): DatabaseContext {
  if (!dbContext) {
    const path = resolveDbPath(dbPath);
    const db = new Database(path);
    initializeDatabase(db);
    dbContext = createContext(db);
  }
  return dbContext;
}

/**
 * Get the database instance (for simple operations).
 */
export function getDatabase(dbPath?: string): Database {
  return getDatabaseContext(dbPath).db;
}

/**
 * Close the database connection.
 */
export function closeDatabase(): void {
  if (dbContext) {
    dbContext.db.close();
    dbContext = null;
  }
}

// ============================================================================
// Re-exports
// ============================================================================

export { createContext } from './transaction';
export type { DatabaseContext } from './transaction';
export { AccountRepository } from './repositories/account';
export { EntityRepository } from './repositories/entity';
export { ChannelRepository } from './repositories/channel';
export { MessageRepository } from './repositories/message';
export { SessionRepository } from './repositories/session';
export { InvitationRepository } from './repositories/invitation';
