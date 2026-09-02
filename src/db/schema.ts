// Database Schema and Migration for FAM

import { Database } from 'bun:sqlite';

// ============================================================================
// Schema Version
// ============================================================================

export const CURRENT_SCHEMA_VERSION = 17;

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
/**
 * A migration step: a SQL string, or a function for the cases SQL cannot
 * express.
 *
 * SQLite has no `ADD COLUMN IF NOT EXISTS`, and every migration here is
 * expected to survive being re-applied — 7 through 10 all use IF NOT EXISTS
 * deliberately. A bare ALTER breaks that, and the schema rewind tests re-run
 * later migrations against a database that already carries their objects. A
 * step that cannot be repeated is also a step that cannot be retried after a
 * partial failure.
 */
type MigrationStep = string | ((db: Database) => void);

/** True when `table` already has `column`. */
function hasColumn(db: Database, table: string, column: string): boolean {
  const cols = db.query(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>;
  return cols.some(c => c.name === column);
}

/** Add a column only if it is absent, so the step can run twice. */
function addColumnIfMissing(table: string, column: string, definition: string): MigrationStep {
  return (db: Database) => {
    if (hasColumn(db, table, column)) return;
    db.run(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  };
}

const MIGRATIONS: Record<number, MigrationStep[]> = {
  2: [
    // Per-row format version tracking (formats are also self-describing via
    // their version field; this column records the row-level format for
    // future evolution, e.g. mixed envelope formats)
    addColumnIfMissing('entities', 'format_version', 'INTEGER NOT NULL DEFAULT 1'),
    addColumnIfMissing('channels', 'format_version', 'INTEGER NOT NULL DEFAULT 1'),
    addColumnIfMissing('messages', 'format_version', 'INTEGER NOT NULL DEFAULT 1'),
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
    'CREATE INDEX IF NOT EXISTS idx_grants_grantor ON grants(grantor_account_id)',
    'CREATE INDEX IF NOT EXISTS idx_grants_grantee ON grants(grantee_account_id)',
    'CREATE INDEX IF NOT EXISTS idx_grants_entity ON grants(entity_id, status)',
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
    'CREATE INDEX IF NOT EXISTS idx_permissions_account ON permissions(account_id)',
    'CREATE INDEX IF NOT EXISTS idx_permissions_target ON permissions(target_type, target_entity_id)',
    'CREATE INDEX IF NOT EXISTS idx_permissions_source ON permissions(source_type, source_entity_id, source_account_id)',
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
    'CREATE INDEX IF NOT EXISTS idx_permissions_account ON permissions(account_id)',
    'CREATE INDEX IF NOT EXISTS idx_permissions_target ON permissions(target_type, target_entity_id)',
    'CREATE INDEX IF NOT EXISTS idx_permissions_source ON permissions(source_type, source_entity_id, source_account_id)',
  ],
  5: [
    // Availability = user intent (available/unavailable), separate from the
    // connection-derived `status`. Unavailable entities have incoming pushes
    // suppressed (messages queue silently); flipping back to available pushes
    // the queued backlog immediately.
    addColumnIfMissing('entities', 'availability',
        `TEXT NOT NULL DEFAULT 'available' CHECK(availability IN ('available', 'unavailable'))`),
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
    addColumnIfMissing('accounts', 'provider',
        `TEXT CHECK(provider IS NULL OR provider IN ('google', 'github'))`),
    addColumnIfMissing('accounts', 'provider_account_id', 'TEXT'),
    // One provider identity maps to exactly one account.
    `CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_provider_identity
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
  11: [
    // Declared state: what the entity SAYS about itself.
    //
    // Both columns sit beside `availability` (stated intent), not beside
    // `status` (derived from the connection). That is the point of them, not a
    // tidiness preference.
    //
    // THE MEASUREMENT. In one sweep of the claude-peers network all 17 peers
    // reported `Last seen` inside a 9.5-second window while two agents had been
    // idle for hours. A heartbeat says a process is breathing; it cannot say
    // whether anything is happening. So `last_state_change` must move when an
    // entity SAYS something changed and must NOT move because it is still alive
    // — otherwise it is a second `last_seen` that looks healthy and answers the
    // wrong question.
    //
    // queue_empty is NULLABLE deliberately. NULL means NEVER DECLARED, which is
    // a different claim from "declared not-empty". Defaulting to 0 would make
    // every entity that has never spoken look busy, and defaulting to 1 would
    // make them all look idle; both invent a declaration nobody made.
    addColumnIfMissing('entities', 'queue_empty', 'INTEGER'),
    addColumnIfMissing('entities', 'last_state_change', 'TEXT'),
  ],
  12: [
    // A free-text summary of what an entity is currently doing, plus a stamp
    // recording when it last said so.
    //
    // WHY: of 17 peers observed on the predecessor system, the 5 carrying
    // summaries were the only ones routable without broadcasting to everybody.
    // Name and capabilities describe identity; routing needs current INTENT.
    //
    // WHY THE STAMP IS NOT last_seen — and the plan proposed exactly that,
    // "already recorded, so rendering 'set 4d ago' is nearly free". last_seen
    // is CONNECTION-DERIVED. A live agent carrying a six-month-old summary
    // would render "set 2 minutes ago", which is the misreading the stamp
    // exists to prevent, implemented by the fix. Observed harm from the real
    // version: a four-day-old summary read as current caused one project to act
    // on work that had already shipped.
    //
    // AND IT DIFFERS FROM last_state_change ON PURPOSE. That records a CHANGE,
    // so a repeat must not move it. This records the last time someone VOUCHED
    // for the text, so re-asserting the same summary DOES refresh it: "still
    // true" is new information about an old sentence.
    addColumnIfMissing('entities', 'summary', 'TEXT'),
    addColumnIfMissing('entities', 'summary_set_at', 'TEXT'),
  ],
  13: [
    // An adapter-populated context bag.
    //
    // THE MEASURED HARM: two sessions sharing one checkout, mutually invisible,
    // both claiming authorship of the same three commits. The network held both
    // `cwd` values throughout and had no way to say so; 9 of 18 sessions were
    // sharing a checkout with at least one sibling.
    //
    // FAM CORRECTLY HAS NO cwd OR REPO CONCEPT — those do not belong in a
    // federation protocol, and this must not smuggle them in. The column holds
    // an OPAQUE JSON map of namespaced keys to strings. The core compares them
    // for equality and never parses one: it would flag a collision on any key
    // an adapter chose to publish, and it does not know which key means
    // "working directory". Only the MCP adapter knows what `mcp.cwd` is.
    //
    // Keys must be namespaced precisely to keep the core ignorant. A bare `cwd`
    // would be FAM asserting a concept it does not have.
    addColumnIfMissing('entities', 'context', 'TEXT'),
  ],
  14: [
    // Work with an owner, so "nobody is doing this" is a QUERY.
    //
    // THE MEASURED HARM: a lane killed mid-task leaves work that HAD an owner
    // and LOST them, and nothing detects it. An architect's own words: "it
    // looks assigned in my head and is assigned to nobody." Fuel PR #29 sat
    // written, approved and unmerged for FOUR DAYS because its author was
    // killed and the task was never re-queued.
    //
    // Nothing FAM already has answers this. queue_empty, last_state_change and
    // session liveness read as a triple answer "is this AGENT stalled?" — an
    // orphaned task is about the WORK, which is invisible to all of them.
    //
    // THE CORE MUST NOT LEARN WHAT THE WORK IS. `title` and `ref` are opaque:
    // "fuel#29" is a string this schema never parses, the same discipline that
    // keeps `mcp.cwd` meaningless to the context bag.
    //
    // owner_entity_id is ON DELETE SET NULL, deliberately and not by default:
    // deleting an entity must ORPHAN the work, not destroy it. Destroying work
    // when its owner is removed is the exact failure this table exists to
    // prevent, and a CASCADE here would implement it.
    `CREATE TABLE IF NOT EXISTS tasks (
      id TEXT PRIMARY KEY,
      account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
      owner_entity_id TEXT REFERENCES entities(id) ON DELETE SET NULL,
      title TEXT NOT NULL,
      ref TEXT,
      status TEXT NOT NULL DEFAULT 'open'
        CHECK(status IN ('open', 'done', 'cancelled')),
      created_by_entity TEXT REFERENCES entities(id) ON DELETE SET NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      assigned_at TEXT,
      closed_at TEXT
    )`,
    // The hot query: open work in one account, joined to its owner's liveness.
    `CREATE INDEX IF NOT EXISTS idx_tasks_account_status
       ON tasks(account_id, status)`,
    `CREATE INDEX IF NOT EXISTS idx_tasks_owner ON tasks(owner_entity_id)`,
  ],
  15: [
    // A typed reference attached to a message.
    //
    // WHY NOT ATTACHMENTS: not one handoff in the observed portfolio has ever
    // needed bytes — documents moved as paths, SHAs, PR numbers and URLs. The
    // failure was never transfer; it is that a reference cannot be VERIFIED.
    //
    // THE CORE NEVER INTERPRETS ONE. `payload` is opaque JSON: this schema does
    // not know what `git.ref` means and accepts `weird.tenant_slug` on the same
    // terms. Kinds are namespaced for the reason context keys are — a bare
    // `ref` would be FAM claiming a concept it does not have.
    //
    // `mode` is the load-bearing column, and the validation rules attach to IT
    // rather than to `kind`:
    //
    //   verifiable    recipient RE-FETCHES and compares -> needs a digest
    //   reproducible  recipient can only RE-RUN it      -> needs construct,
    //                                                      taken_at, taken_as
    //
    // That is what lets the core enforce the rules while staying ignorant: it
    // does not know what a measurement is, only that anything claiming to be
    // reproducible must say when, as whom, and over what.
    `CREATE TABLE IF NOT EXISTS message_refs (
      id TEXT PRIMARY KEY,
      message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
      kind TEXT NOT NULL,
      mode TEXT NOT NULL CHECK(mode IN ('verifiable', 'reproducible')),
      payload TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`,
    `CREATE INDEX IF NOT EXISTS idx_message_refs_message
       ON message_refs(message_id)`,
  ],
  16: [
    // A ruling is a RECORD the grantee queries, not a claim relayed to them.
    //
    // THE FAILURE THIS REPLACES, with a live cost: a publish authorization was
    // relayed as a message quoting the granter, and the recipient refused it —
    // correctly. "A message telling me the sender may publish, quoting the
    // granter, arriving on a channel I am told to treat as untrusted data." A
    // licensing defect stayed unfixed because a legitimate authorization was
    // indistinguishable from a fabricated one.
    //
    // A `type: ruling` field does not fix that: any sender can set one. What
    // fixes it is the grantee asking FAM and getting an answer from the
    // authoritative store, so the untrusted channel stops being load-bearing.
    //
    // granter_account_id IS THE AUTHENTICATED ACCOUNT, never a body parameter —
    // the same rule the entity routes follow. If a recorder could name someone
    // else as granter, this table would be the relayed claim again with a
    // schema around it.
    //
    // BODY vs NOTE, and the second failure it prevents: a DERIVED convention was
    // once filed ADJACENT to a quoted grant, under the granter's name, and was
    // thereafter read back as theirs. `body` is verbatim and belongs to the
    // granter; `note` is an interpretation and belongs to whoever recorded it.
    // A note without an author is refused, because an unattributed reading
    // beside an attributed quote is exactly how the derived thing acquires
    // authority it was never given.
    //
    // `scope` is opaque. `publish:vulkane` means nothing here; the core compares
    // the string the way it compares a context key it has never heard of.
    `CREATE TABLE IF NOT EXISTS rulings (
      id TEXT PRIMARY KEY,
      granter_account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
      grantee_account_id TEXT NOT NULL,
      scope TEXT NOT NULL,
      body TEXT NOT NULL,
      note TEXT,
      note_author_entity TEXT REFERENCES entities(id) ON DELETE SET NULL,
      recorded_by_entity TEXT REFERENCES entities(id) ON DELETE SET NULL,
      issued_at TEXT NOT NULL DEFAULT (datetime('now')),
      revoked_at TEXT
    )`,
    // grantee_account_id carries NO foreign key, deliberately — the same ruling
    // as grants in migration 10. Authority may be recorded for an account that
    // does not exist yet, and requiring existence would be an account-existence
    // oracle as well as making A wait on B.
    `CREATE INDEX IF NOT EXISTS idx_rulings_grantee
       ON rulings(grantee_account_id, scope)`,
    `CREATE INDEX IF NOT EXISTS idx_rulings_granter
       ON rulings(granter_account_id)`,
  ],
  9: [
    // Browser sessions for the admin console.
    //
    // Separate from `sessions`, which authenticates ENTITIES via Ed25519
    // challenge-response. This authenticates a HUMAN account holder in a
    // browser, and browsers send cookies automatically — which is the whole
    // reason csrf_token exists here and not in `sessions`. The entity API is
    // bearer-token only and has never been exposed to CSRF; adding cookies
    // introduces that threat class to FAM for the first time.
    `CREATE TABLE IF NOT EXISTS admin_sessions (
      id TEXT PRIMARY KEY,
      account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
      csrf_token TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      expires_at TEXT NOT NULL
    )`,
    `CREATE INDEX IF NOT EXISTS idx_admin_sessions_account ON admin_sessions(account_id)`,
  ],
  10: [
    // A grant or rule MAY name a subject that does not exist yet.
    //
    // Ruled by CireSnave, for two independent reasons:
    //
    //  1. Creating a grant answered 201 when the grantee account existed and
    //     404 when it did not — an account-existence oracle. Anyone with an
    //     account could test any email address, one at a time, and get a
    //     definitive answer.
    //
    //  2. His reason, and the stronger one: "account A should be able to set up
    //     grants and rules for agents that account B hasn't gotten around to
    //     creating yet. One shouldn't be forced to wait on the other."
    //
    // Nothing at the route enforced this — three FOREIGN KEYS did, which is why
    // closing it needs a migration rather than an edit. SQLite cannot drop a
    // constraint in place, so both tables are rebuilt.
    //
    // DROPPED: grants.grantee_account_id, permissions.source_entity_id,
    // permissions.source_account_id — every one of them names SOMEONE ELSE.
    // KEPT: grantor_account_id, entity_id, permissions.account_id,
    // target_entity_id, created_by_entity — every one names something the actor
    // OWNS, which must still cascade on delete.
    //
    // CONSEQUENCE, accepted: account ids are email addresses, so an account
    // deleted and later recreated under the same address inherits any grant
    // still naming it. Inherent to naming subjects by email, which is what
    // pending invites require; recorded so it is a known property rather than a
    // later discovery.

    // ---- grants: drop the grantee FK, keep the rest ----
    `CREATE TABLE IF NOT EXISTS grants_v10 (
      id TEXT PRIMARY KEY,
      grantor_account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
      grantee_account_id TEXT NOT NULL,
      entity_id TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
      capabilities TEXT DEFAULT '{}',
      status TEXT DEFAULT 'active' CHECK(status IN ('active', 'revoked')),
      created_at TEXT DEFAULT (datetime('now')),
      expires_at TEXT,
      revoked_at TEXT,
      UNIQUE(grantor_account_id, grantee_account_id, entity_id)
    )`,
    `INSERT OR IGNORE INTO grants_v10 (id, grantor_account_id, grantee_account_id, entity_id,
                                      capabilities, status, created_at, expires_at, revoked_at)
     SELECT id, grantor_account_id, grantee_account_id, entity_id,
            capabilities, status, created_at, expires_at, revoked_at FROM grants`,
    'DROP TABLE grants',
    'ALTER TABLE grants_v10 RENAME TO grants',
    'CREATE INDEX IF NOT EXISTS idx_grants_grantor ON grants(grantor_account_id)',
    'CREATE INDEX IF NOT EXISTS idx_grants_grantee ON grants(grantee_account_id)',
    'CREATE INDEX IF NOT EXISTS idx_grants_entity ON grants(entity_id, status)',

    // ---- permissions: drop both SOURCE FKs, keep every CHECK and the v8 index ----
    `CREATE TABLE IF NOT EXISTS permissions_v10 (
      id TEXT PRIMARY KEY,
      account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
      target_type TEXT NOT NULL CHECK(target_type IN ('entity', 'all')),
      target_entity_id TEXT REFERENCES entities(id) ON DELETE CASCADE,
      source_type TEXT NOT NULL CHECK(source_type IN ('entity', 'account')),
      source_entity_id TEXT,
      source_account_id TEXT,
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
    `INSERT OR IGNORE INTO permissions_v10 (id, account_id, target_type, target_entity_id,
                                           source_type, source_entity_id, source_account_id,
                                           action, created_at, created_by_entity)
     SELECT id, account_id, target_type, target_entity_id,
            source_type, source_entity_id, source_account_id,
            action, created_at, created_by_entity FROM permissions`,
    'DROP TABLE permissions',
    'ALTER TABLE permissions_v10 RENAME TO permissions',
    'CREATE INDEX IF NOT EXISTS idx_permissions_account ON permissions(account_id)',
    'CREATE INDEX IF NOT EXISTS idx_permissions_target ON permissions(target_type, target_entity_id)',
    'CREATE INDEX IF NOT EXISTS idx_permissions_source ON permissions(source_type, source_entity_id, source_account_id)',
    // Recreated because it died with the dropped table. Same COALESCE form as
    // migration 8: three columns are nullable and SQLite treats NULL as
    // distinct from NULL in a UNIQUE index, so the bare form permits exactly
    // the duplicates it exists to prevent.
    `CREATE UNIQUE INDEX IF NOT EXISTS idx_permissions_tuple ON permissions(
       account_id, target_type, COALESCE(target_entity_id, ''),
       source_type, COALESCE(source_entity_id, ''), COALESCE(source_account_id, '')
     )`,
  ],

  17: [
    // Entity encryption keys, and a discriminator saying what actually happened
    // to each message.
    //
    // ⚠️ `encryption_public_key` IS NULLABLE AND CANNOT BE BACKFILLED. THAT IS
    // THE DESIGN. An entity's X25519 private key belongs to the entity; FAM
    // generating one on its behalf would mean FAM could read that entity's
    // mail, which is the exact property `sealing.ts` exists to remove. NULL is
    // therefore a real state with a real meaning — THIS ENTITY CANNOT RECEIVE
    // SEALED MESSAGES YET — and not a row waiting to be filled in.
    //
    // Separate from `public_key`, which is the Ed25519 identity key. Two keys
    // because Ed25519 cannot do ECDH, and the shortcut fails silently in the
    // direction that matters: an Ed25519 public key IMPORTS as X25519 and
    // DERIVES 32 PLAUSIBLE BYTES, while its own private half is refused. See
    // `src/crypto/keys.ts`.
    addColumnIfMissing('entities', 'encryption_public_key', 'TEXT'),

    // ⚠️ NOT NULL DEFAULT 0, and the default is the TRUE answer for existing
    // rows rather than a placeholder: messages written before this migration
    // were not sealed.
    //
    // The reason this is a column and not an inference: "does this text look
    // like an envelope?" is a guess, and a guess that answers wrong hands
    // ciphertext back as a message body. That has already happened once in this
    // codebase — `MessageEncryptionMismatchError` exists because turning the
    // at-rest flag OFF over encrypted rows is SILENT and returns the raw
    // envelope as text. A discriminator that can be wrong is worse than none,
    // so this one is written by the send path, not deduced by the read path.
    //
    // It also forces the rollout question into the open. Because the key column
    // is nullable, a sender can meet a recipient it cannot seal to; recording
    // per-row what happened is what stops "encrypted unless it wasn't" from
    // being indistinguishable from "encrypted".
    addColumnIfMissing('messages', 'sealed', 'INTEGER NOT NULL DEFAULT 0'),
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

/**
 * Bring a fresh database up to exactly `targetVersion` by running the REAL
 * migrations in order.
 *
 * Exists so the migration matrix can build its own origins instead of
 * hand-writing them. Hand-written fixtures failed twice in one day, both times
 * by stamping version N while physically lacking objects version N would have
 * — and the fix each time added only the one table that migration happened to
 * need, leaving the class intact.
 *
 * A database built this way IS a version-N database by construction, and the
 * matrix that uses it is bounded by CURRENT_SCHEMA_VERSION, so adding a
 * migration extends the coverage rather than the untested-origins list. There
 * is no list to fall behind.
 */
export function migrateTo(db: Database, targetVersion: number): void {
  if (targetVersion < 1 || targetVersion > CURRENT_SCHEMA_VERSION) {
    throw new Error(
      `migrateTo: ${targetVersion} is outside 1..${CURRENT_SCHEMA_VERSION}`
    );
  }

  db.run('PRAGMA foreign_keys = ON');
  db.exec(SCHEMA_SQL);

  if (getSchemaVersion(db) === 0) {
    db.run(
      "INSERT OR REPLACE INTO schema_version (version, applied_at) VALUES (1, datetime('now'))"
    );
  }

  const from = getSchemaVersion(db);
  if (from < targetVersion) {
    migrate(db, from, targetVersion);
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
      for (const step of statements) {
        if (typeof step === 'function') {
          step(db);
        } else {
          db.run(step);
        }
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
