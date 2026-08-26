// Database Schema and Migration for FAM

import { Database } from 'bun:sqlite';

// ============================================================================
// Schema Version
// ============================================================================

const CURRENT_SCHEMA_VERSION = 8;

// ============================================================================
// Schema Definition (base — v1)
// ============================================================================
// NOTE: SCHEMA_SQL defines the v1 baseline. Changes to the schema after v1
// MUST be expressed as migrations in MIGRATIONS below — do not edit SCHEMA_SQL
// for post-v1 changes. Fresh databases run the base schema, then apply all
// pending migrations, so they end at CURRENT_SCHEMA_VERSION.

const SCHEMA_SQL = `
  -- Schema version tracking
  CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT DEFAULT (datetime('now'))
  );

  -- Accounts table
  CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,           -- email address
    display_name TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
  );

  -- Server authorizations
  CREATE TABLE IF NOT EXISTS authorizations (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    server_id TEXT NOT NULL,       -- which FAM server is authorized
    token_hash TEXT NOT NULL,
    granted_at TEXT DEFAULT (datetime('now')),
    expires_at TEXT,
    revoked_at TEXT,
    UNIQUE(account_id, server_id)
  );

  -- Entities table
  CREATE TABLE IF NOT EXISTS entities (
    id TEXT PRIMARY KEY,           -- name@account
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    type TEXT NOT NULL CHECK(type IN ('agent', 'human', 'tool')),
    display_name TEXT,
    capabilities TEXT DEFAULT '{}', -- JSON
    location_server TEXT,          -- which FAM server it's currently on
    public_key TEXT NOT NULL,      -- base64-encoded
    status TEXT DEFAULT 'offline', -- online, offline, away
    created_at TEXT DEFAULT (datetime('now')),
    last_seen TEXT
  );

  -- Channels table
  CREATE TABLE IF NOT EXISTS channels (
    id TEXT PRIMARY KEY,           -- UUID
    name TEXT NOT NULL,
    created_by_entity TEXT REFERENCES entities(id) ON DELETE SET NULL,
    is_public INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );

  -- Channel members
  CREATE TABLE IF NOT EXISTS channel_members (
    channel_id TEXT REFERENCES channels(id) ON DELETE CASCADE,
    entity_id TEXT REFERENCES entities(id) ON DELETE CASCADE,
    role TEXT DEFAULT 'member' CHECK(role IN ('owner', 'admin', 'member')),
    joined_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (channel_id, entity_id)
  );

  -- Messages table
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    channel_id TEXT REFERENCES channels(id) ON DELETE SET NULL,
    from_entity TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    to_entity TEXT REFERENCES entities(id) ON DELETE CASCADE,
    text TEXT NOT NULL,
    sent_at TEXT DEFAULT (datetime('now')),
    delivered INTEGER DEFAULT 0
  );

  -- Active sessions (for online entities)
  CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,           -- session UUID
    entity_id TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    connected_at TEXT DEFAULT (datetime('now')),
    last_heartbeat TEXT DEFAULT (datetime('now')),
    websocket_id TEXT
  );

  -- Pending challenges for entity authentication
  CREATE TABLE IF NOT EXISTS challenges (
    entity_id TEXT PRIMARY KEY REFERENCES entities(id) ON DELETE CASCADE,
    nonce TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );

  -- OAuth state parameter storage (persists across server restarts)
  CREATE TABLE IF NOT EXISTS oauth_states (
    state TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );

  -- Channel invitations
  CREATE TABLE IF NOT EXISTS channel_invitations (
    id TEXT PRIMARY KEY,           -- UUID
    channel_id TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    invited_by TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    invited_entity TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'accepted', 'declined', 'expired')),
    created_at TEXT DEFAULT (datetime('now')),
    expires_at TEXT,
    UNIQUE(channel_id, invited_entity)
  );

  -- Channel bans
  CREATE TABLE IF NOT EXISTS channel_bans (
    channel_id TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    entity_id TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    banned_by TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    reason TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    expires_at TEXT,
    PRIMARY KEY (channel_id, entity_id)
  );

  -- Indexes for common queries
  CREATE INDEX IF NOT EXISTS idx_entities_account ON entities(account_id);
  CREATE INDEX IF NOT EXISTS idx_entities_status ON entities(status);
  CREATE INDEX IF NOT EXISTS idx_messages_channel ON messages(channel_id);
  CREATE INDEX IF NOT EXISTS idx_messages_to ON messages(to_entity, delivered);
  CREATE INDEX IF NOT EXISTS idx_messages_from ON messages(from_entity);
  CREATE INDEX IF NOT EXISTS idx_messages_sent ON messages(sent_at);
  CREATE INDEX IF NOT EXISTS idx_sessions_entity ON sessions(entity_id);
  CREATE INDEX IF NOT EXISTS idx_channel_members_entity ON channel_members(entity_id);
  CREATE INDEX IF NOT EXISTS idx_authorizations_account ON authorizations(account_id);
  CREATE INDEX IF NOT EXISTS idx_authorizations_token ON authorizations(token_hash);
  CREATE INDEX IF NOT EXISTS idx_oauth_states_provider ON oauth_states(provider);
  CREATE INDEX IF NOT EXISTS idx_channel_invitations_entity ON channel_invitations(invited_entity, status);
  CREATE INDEX IF NOT EXISTS idx_channel_bans_entity ON channel_bans(entity_id);
`;

// ============================================================================
// Migration Functions
// ============================================================================

/**
 * Registry of schema migrations, keyed by the version they migrate TO.
 * Each migration runs in its own transaction; a failed migration rolls back
 * and aborts startup.
 */
const MIGRATIONS: Record<number, string[]> = {
  2: [
    // Per-row format version tracking (formats are also self-describing via
    // their version field; this column records the row-level format for
    // future evolution, e.g. mixed envelope formats)
    'ALTER TABLE entities ADD COLUMN format_version INTEGER NOT NULL DEFAULT 1',
    'ALTER TABLE channels ADD COLUMN format_version INTEGER NOT NULL DEFAULT 1',
    'ALTER TABLE messages ADD COLUMN format_version INTEGER NOT NULL DEFAULT 1',
  ],
  3: [
    // Cross-account grants: default-deny messaging; an active grant from the
    // target's account to the sender's account is required for cross-account DMs
    // (IF NOT EXISTS keeps the migration safe to re-apply on hand-built DBs)
    `CREATE TABLE IF NOT EXISTS grants (
      id TEXT PRIMARY KEY,
      grantor_account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
      grantee_account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
      entity_id TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
      capabilities TEXT DEFAULT '{}',
      status TEXT DEFAULT 'active' CHECK(status IN ('active', 'revoked')),
      created_at TEXT DEFAULT (datetime('now')),
      expires_at TEXT,
      revoked_at TEXT,
      UNIQUE(grantor_account_id, grantee_account_id, entity_id)
    )`,
    'CREATE INDEX idx_grants_grantor ON grants(grantor_account_id)',
    'CREATE INDEX idx_grants_grantee ON grants(grantee_account_id)',
    'CREATE INDEX idx_grants_entity ON grants(entity_id, status)',
    // Permission matrix: per-account allow/deny rules protecting the account's
    // entities from specific entities or entire accounts
    `CREATE TABLE IF NOT EXISTS permissions (
      id TEXT PRIMARY KEY,
      account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
      target_type TEXT NOT NULL CHECK(target_type IN ('entity', 'all')),
      target_entity_id TEXT REFERENCES entities(id) ON DELETE CASCADE,
      source_type TEXT NOT NULL CHECK(source_type IN ('entity', 'account')),
      source_entity_id TEXT REFERENCES entities(id) ON DELETE CASCADE,
      source_account_id TEXT REFERENCES accounts(id) ON DELETE CASCADE,
      action TEXT NOT NULL CHECK(action IN ('allow', 'deny')),
      created_at TEXT DEFAULT (datetime('now')),
      created_by_entity TEXT REFERENCES entities(id) ON DELETE SET NULL
    )`,
    'CREATE INDEX idx_permissions_account ON permissions(account_id)',
    'CREATE INDEX idx_permissions_target ON permissions(target_type, target_entity_id)',
    'CREATE INDEX idx_permissions_source ON permissions(source_type, source_entity_id, source_account_id)',
    // Channel bans retired in favor of the permission matrix (channel
    // moderation is kick + set-role; cross-account blocking is account-scoped)
    'DROP INDEX IF EXISTS idx_channel_bans_entity',
    'DROP TABLE IF EXISTS channel_bans',
  ],
  4: [
    // Harden permissions with CHECK constraints (defense in depth behind the
    // route-level validation): enforce NULL/NOT-NULL pairing per rule shape
    // so ambiguous rows (e.g. target_type='all' with a target_entity_id)
    // cannot exist. SQLite cannot ALTER to add CHECKs — rebuild the table.
    `CREATE TABLE permissions_v4 (
      id TEXT PRIMARY KEY,
      account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
      target_type TEXT NOT NULL CHECK(target_type IN ('entity', 'all')),
      target_entity_id TEXT REFERENCES entities(id) ON DELETE CASCADE,
      source_type TEXT NOT NULL CHECK(source_type IN ('entity', 'account')),
      source_entity_id TEXT REFERENCES entities(id) ON DELETE CASCADE,
      source_account_id TEXT REFERENCES accounts(id) ON DELETE CASCADE,
      action TEXT NOT NULL CHECK(action IN ('allow', 'deny')),
      created_at TEXT DEFAULT (datetime('now')),
      created_by_entity TEXT REFERENCES entities(id) ON DELETE SET NULL,
      CHECK (target_type != 'entity' OR target_entity_id IS NOT NULL),
      CHECK (target_type != 'all' OR target_entity_id IS NULL),
      CHECK (source_type != 'entity' OR source_entity_id IS NOT NULL),
      CHECK (source_type != 'entity' OR source_account_id IS NULL),
      CHECK (source_type != 'account' OR source_account_id IS NOT NULL),
      CHECK (source_type != 'account' OR source_entity_id IS NULL)
    )`,
    `INSERT INTO permissions_v4 (id, account_id, target_type, target_entity_id, source_type, source_entity_id, source_account_id, action, created_at, created_by_entity)
     SELECT id, account_id, target_type,
            CASE WHEN target_type = 'all' THEN NULL ELSE target_entity_id END,
            source_type,
            CASE WHEN source_type = 'entity' THEN source_entity_id ELSE NULL END,
            CASE WHEN source_type = 'account' THEN source_account_id ELSE NULL END,
            action, created_at, created_by_entity
     FROM permissions`,
    'DROP TABLE permissions',
    'ALTER TABLE permissions_v4 RENAME TO permissions',
    'CREATE INDEX idx_permissions_account ON permissions(account_id)',
    'CREATE INDEX idx_permissions_target ON permissions(target_type, target_entity_id)',
    'CREATE INDEX idx_permissions_source ON permissions(source_type, source_entity_id, source_account_id)',
  ],
  5: [
    // Availability = user intent (available/unavailable), separate from the
    // connection-derived `status`. Unavailable entities have incoming pushes
    // suppressed (messages queue silently); flipping back to available pushes
    // the queued backlog immediately.
    `ALTER TABLE entities ADD COLUMN availability TEXT NOT NULL DEFAULT 'available'
      CHECK(availability IN ('available', 'unavailable'))`,
  ],
  6: [
    // Bind each account to the identity provider that created it.
    //
    // Account ids are email addresses, and before this an OAuth callback
    // matched on email alone. GitHub's /user endpoint returns the user's
    // PUBLIC PROFILE email — user-settable and never verified by GitHub — so
    // setting a GitHub profile email to a victim's Google address and signing
    // in through GitHub yielded a valid token for the victim's account.
    //
    // provider_account_id is the provider's own stable user id (Google `sub`
    // / GitHub numeric id), which the user cannot choose. Matching on
    // (provider, provider_account_id) rather than on an email string is what
    // actually closes the takeover; the email becomes a label rather than a key.
    //
    // Nullable because pre-v6 rows predate the binding. They adopt a provider
    // on the next successful login (trust-on-first-use); there are no such
    // rows in any deployed database today.
    `ALTER TABLE accounts ADD COLUMN provider TEXT
      CHECK(provider IS NULL OR provider IN ('google', 'github'))`,
    'ALTER TABLE accounts ADD COLUMN provider_account_id TEXT',
    // One provider identity maps to exactly one account.
    `CREATE UNIQUE INDEX idx_accounts_provider_identity
       ON accounts(provider, provider_account_id)
       WHERE provider IS NOT NULL AND provider_account_id IS NOT NULL`,
  ],
  7: [
    // Per-recipient delivery tracking.
    //
    // `messages.delivered` is a SINGLE flag shared by every recipient of a
    // channel message. One member acknowledging flipped it for everyone, so a
    // member who was offline — or paused via availability — never received it.
    // The column answered "has anyone seen this?" while every caller read it as
    // "has THIS entity seen this?".
    //
    // Delivery is a property of (message, recipient), so it gets its own rows.
    `CREATE TABLE IF NOT EXISTS message_deliveries (
      message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
      recipient_entity_id TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
      delivered INTEGER NOT NULL DEFAULT 0,
      delivered_at TEXT,
      PRIMARY KEY (message_id, recipient_entity_id)
    )`,
    // The hot path: "what is waiting for this entity?" runs on every
    // authenticate and every availability flush.
    `CREATE INDEX IF NOT EXISTS idx_message_deliveries_recipient
       ON message_deliveries(recipient_entity_id, delivered)`,

    // Backfill DMs: exactly one recipient, and the old flag was accurate.
    `INSERT OR IGNORE INTO message_deliveries (message_id, recipient_entity_id, delivered)
     SELECT id, to_entity, delivered FROM messages WHERE to_entity IS NOT NULL`,

    // Backfill channel messages from CURRENT membership, excluding the sender.
    //
    // Known imprecision, accepted deliberately: membership now is not
    // membership at send time. Someone who has since left loses a backlog they
    // may never have read, and someone who has since joined inherits history
    // addressed to the channel before them — carrying the old flag, so
    // anything already marked delivered stays delivered rather than
    // resurfacing. Send-time membership was never recorded, so it cannot be
    // reconstructed. From here fan-out happens at send time and the question
    // does not arise again.
    `INSERT OR IGNORE INTO message_deliveries (message_id, recipient_entity_id, delivered)
     SELECT m.id, cm.entity_id, m.delivered
     FROM messages m
     JOIN channel_members cm ON cm.channel_id = m.channel_id
     WHERE m.channel_id IS NOT NULL AND cm.entity_id != m.from_entity`,
  ],
  8: [
    // Make the permission-rule uniqueness invariant SCHEMA-enforced.
    //
    // It was held only by permissions.create() doing findIdentical-then-insert
    // with no await between them — true today because that is uninterruptible
    // against the event loop, but a property of the current single-process
    // server rather than of the data. Demonstrated: opening that window
    // produces 4 duplicate rules from 20 concurrent requests.
    //
    // It also matters for the permission RESOLVER, which documents that ties at
    // equal specificity are impossible because the tuple is unique. That
    // comment asserted an invariant nothing enforced.
    //
    // Dedupe before indexing — an existing duplicate would abort the migration.
    // Keep the earliest row per tuple: it is the one whose effect callers have
    // already observed.
    `DELETE FROM permissions WHERE rowid NOT IN (
       SELECT MIN(rowid) FROM permissions
       GROUP BY account_id, target_type, COALESCE(target_entity_id, ''),
                source_type, COALESCE(source_entity_id, ''),
                COALESCE(source_account_id, '')
     )`,
    // COALESCE, not the bare columns: three of them are nullable, and SQLite
    // treats NULL as distinct from NULL in a UNIQUE index — so a plain unique
    // index would permit exactly the duplicates this exists to prevent.
    `CREATE UNIQUE INDEX IF NOT EXISTS idx_permissions_tuple ON permissions(
       account_id, target_type, COALESCE(target_entity_id, ''),
       source_type, COALESCE(source_entity_id, ''), COALESCE(source_account_id, '')
     )`,
  ],
};

export function initializeDatabase(db: Database): void {
  // Enable WAL mode for better concurrency
  db.run('PRAGMA journal_mode = WAL');
  db.run('PRAGMA busy_timeout = 3000');
  db.run('PRAGMA foreign_keys = ON');
  
  // Apply base schema (v1)
  db.exec(SCHEMA_SQL);
  
  // Fresh databases have an empty schema_version — stamp the v1 baseline
  let currentVersion = getSchemaVersion(db);
  if (currentVersion === 0) {
    db.run("INSERT OR REPLACE INTO schema_version (version, applied_at) VALUES (1, datetime('now'))");
    currentVersion = 1;
  }
  
  // Apply pending migrations
  if (currentVersion < CURRENT_SCHEMA_VERSION) {
    migrate(db, currentVersion, CURRENT_SCHEMA_VERSION);
  }
}

function getSchemaVersion(db: Database): number {
  try {
    const result = db.query('SELECT MAX(version) as version FROM schema_version').get() as { version: number } | null;
    return result?.version ?? 0;
  } catch {
    return 0;
  }
}

function migrate(db: Database, fromVersion: number, toVersion: number): void {
  for (let v = fromVersion + 1; v <= toVersion; v++) {
    const statements = MIGRATIONS[v];
    if (!statements) {
      throw new Error(`No migration registered for schema version ${v}`);
    }
    
    db.run('BEGIN');
    try {
      for (const sql of statements) {
        db.run(sql);
      }
      db.run('INSERT OR REPLACE INTO schema_version (version, applied_at) VALUES (?, datetime(\'now\'))', [v]);
      db.run('COMMIT');
    } catch (e) {
      db.run('ROLLBACK');
      throw new Error(`Schema migration to version ${v} failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
}

// ============================================================================
// Cleanup Functions
// ============================================================================

/**
 * Remove expired challenges (older than 5 minutes).
 */
export function cleanupExpiredChallenges(db: Database): void {
  db.run(
    "DELETE FROM challenges WHERE created_at < datetime('now', '-5 minutes')"
  );
}

/**
 * Remove stale sessions (no heartbeat in 60 seconds).
 */
export function cleanupStaleSessions(db: Database): void {
  db.run(
    "DELETE FROM sessions WHERE last_heartbeat < datetime('now', '-60 seconds')"
  );
  
  // Update entity status to offline for deleted sessions
  db.run(`
    UPDATE entities 
    SET status = 'offline' 
    WHERE status = 'online' 
    AND id NOT IN (SELECT entity_id FROM sessions)
  `);
}

/**
 * Remove expired OAuth states (older than 10 minutes).
 */
export function cleanupExpiredOAuthStates(db: Database): void {
  db.run(
    "DELETE FROM oauth_states WHERE created_at < datetime('now', '-10 minutes')"
  );
}

/**
 * Remove expired channel invitations (older than 7 days).
 */
export function cleanupExpiredInvitations(db: Database): void {
  db.run(
    "DELETE FROM channel_invitations WHERE status = 'pending' AND created_at < datetime('now', '-7 days')"
  );
}
