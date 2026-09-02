// Transaction Helper for Database Operations

import { Database } from 'bun:sqlite';

// ============================================================================
// Transaction Helper
// ============================================================================

/**
 * Execute a function within a database transaction.
 * Automatically commits on success, rolls back on error.
 */
export function transaction<T>(db: Database, fn: () => T): T {
  db.run('BEGIN');
  try {
    const result = fn();
    db.run('COMMIT');
    return result;
  } catch (e) {
    db.run('ROLLBACK');
    throw e;
  }
}

/**
 * Execute an async function within a database transaction.
 * Automatically commits on success, rolls back on error.
 */
export async function transactionAsync<T>(db: Database, fn: () => Promise<T>): Promise<T> {
  db.run('BEGIN');
  try {
    const result = await fn();
    db.run('COMMIT');
    return result;
  } catch (e) {
    db.run('ROLLBACK');
    throw e;
  }
}

// ============================================================================
// Database Context with Transaction Support
// ============================================================================

import { AccountRepository } from './repositories/account';
import { EntityRepository } from './repositories/entity';
import { ChannelRepository } from './repositories/channel';
import { MessageRepository } from './repositories/message';
import { SessionRepository } from './repositories/session';
import { AdminSessionRepository } from './repositories/adminSession';
import { InvitationRepository } from './repositories/invitation';
import { GrantRepository } from './repositories/grant';
import { PermissionRepository } from './repositories/permission';
import { TaskRepository } from './repositories/task';
import { MessageRefRepository } from './repositories/messageRef';
import { RulingRepository } from './repositories/ruling';
import { VoucherRepository } from './repositories/voucher';

export interface DatabaseContext {
  db: Database;
  accounts: AccountRepository;
  entities: EntityRepository;
  channels: ChannelRepository;
  messages: MessageRepository;
  sessions: SessionRepository;
  adminSessions: AdminSessionRepository;
  invitations: InvitationRepository;
  grants: GrantRepository;
  permissions: PermissionRepository;
  tasks: TaskRepository;
  messageRefs: MessageRefRepository;
  rulings: RulingRepository;
  vouchers: VoucherRepository;

  /**
   * Execute a function within a transaction.
   */
  transaction: <T>(fn: () => T) => T;

  /**
   * Execute an async function within a transaction.
   */
  transactionAsync: <T>(fn: () => Promise<T>) => Promise<T>;
}

export function createContext(db: Database): DatabaseContext {
  const accounts = new AccountRepository(db);
  const entities = new EntityRepository(db);
  const channels = new ChannelRepository(db);
  const messages = new MessageRepository(db);
  const sessions = new SessionRepository(db);
  const adminSessions = new AdminSessionRepository(db);
  const invitations = new InvitationRepository(db);
  const grants = new GrantRepository(db);
  const permissions = new PermissionRepository(db);
  const tasks = new TaskRepository(db);
  const messageRefs = new MessageRefRepository(db);
  const rulings = new RulingRepository(db);
  const vouchers = new VoucherRepository(db);

  return {
    db,
    accounts,
    entities,
    channels,
    messages,
    sessions,
    adminSessions,
    invitations,
    grants,
    permissions,
    tasks,
    messageRefs,
    rulings,
    vouchers,
    transaction: (fn) => transaction(db, fn),
    transactionAsync: (fn) => transactionAsync(db, fn),
  };
}
