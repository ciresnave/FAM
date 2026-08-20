import { test, expect, describe } from 'bun:test';
import { Database } from 'bun:sqlite';
import { initializeDatabase } from '../schema';

describe('Schema Migrations', () => {
  test('fresh database initializes at current schema version with v2-v6 objects', () => {
    const db = new Database(':memory:');
    initializeDatabase(db);

    const version = db
      .query('SELECT MAX(version) as version FROM schema_version')
      .get() as { version: number };
    expect(version.version).toBe(6);

    // v2 columns exist on all three tables
    for (const table of ['entities', 'channels', 'messages']) {
      const cols = db
        .query(`PRAGMA table_info(${table})`)
        .all() as Array<{ name: string }>;
      const names = cols.map(c => c.name);
      expect(names).toContain('format_version');
    }

    // v5: entities.availability exists with default
    const entityCols = db
      .query('PRAGMA table_info(entities)')
      .all() as Array<{ name: string; dflt_value: string | null }>;
    const availabilityCol = entityCols.find(c => c.name === 'availability');
    expect(availabilityCol).toBeDefined();
    expect(availabilityCol!.dflt_value).toContain('available');

    // v3: grants and permissions tables exist
    const grants = db
      .query("SELECT name FROM sqlite_master WHERE type='table' AND name='grants'")
      .get();
    expect(grants).not.toBeNull();
    const permissions = db
      .query("SELECT name FROM sqlite_master WHERE type='table' AND name='permissions'")
      .get();
    expect(permissions).not.toBeNull();

    // v3: channel_bans retired
    const bans = db
      .query("SELECT name FROM sqlite_master WHERE type='table' AND name='channel_bans'")
      .get();
    expect(bans).toBeNull();

    // Default value applied on insert (spot check via messages table)
    db.run(
      `INSERT INTO accounts (id) VALUES ('mig@example.com')`
    );
    db.run(
      `INSERT INTO entities (id, account_id, type, public_key) VALUES ('m@mig@example.com', 'mig@example.com', 'agent', 'pk')`
    );
    db.run(
      `INSERT INTO messages (from_entity, text) VALUES ('m@mig@example.com', 'hello')`
    );
    const row = db
      .query('SELECT format_version FROM messages')
      .get() as { format_version: number };
    expect(row.format_version).toBe(1);

    db.close();
  });

  test('existing v1 database upgrades to v2 in place', () => {
    // Build a v1 database the way the old code left it:
    // base tables + schema_version row = 1, WITHOUT migration columns.
    // (schema.ts keeps SCHEMA_SQL as the v1 baseline; this simulates an
    // existing deployment before re-running initializeDatabase.)
    const db1 = new Database(':memory:');
    db1.exec('PRAGMA foreign_keys = ON');
    db1.exec(`
      CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at TEXT DEFAULT (datetime('now')));
      CREATE TABLE accounts (
        id TEXT PRIMARY KEY, display_name TEXT,
        created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now'))
      );
      CREATE TABLE entities (
        id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        type TEXT NOT NULL, display_name TEXT, capabilities TEXT DEFAULT '{}',
        location_server TEXT, public_key TEXT NOT NULL,
        status TEXT DEFAULT 'offline', created_at TEXT DEFAULT (datetime('now')), last_seen TEXT
      );
      CREATE TABLE channels (
        id TEXT PRIMARY KEY, name TEXT NOT NULL,
        created_by_entity TEXT REFERENCES entities(id) ON DELETE SET NULL,
        is_public INTEGER DEFAULT 0, created_at TEXT DEFAULT (datetime('now'))
      );
      CREATE TABLE messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        channel_id TEXT REFERENCES channels(id) ON DELETE SET NULL,
        from_entity TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
        to_entity TEXT REFERENCES entities(id) ON DELETE CASCADE,
        text TEXT NOT NULL, sent_at TEXT DEFAULT (datetime('now')), delivered INTEGER DEFAULT 0
      );
      INSERT INTO schema_version (version) VALUES (1);
      INSERT INTO accounts (id) VALUES ('old@example.com');
      INSERT INTO entities (id, account_id, type, public_key)
        VALUES ('old@old@example.com', 'old@example.com', 'agent', 'pk');
      INSERT INTO messages (from_entity, text) VALUES ('old@old@example.com', 'pre-migration');
    `);

    // Run initializeDatabase — it should detect v1 and apply migrations 2-5
    initializeDatabase(db1);

    const version = db1
      .query('SELECT MAX(version) as version FROM schema_version')
      .get() as { version: number };
    expect(version.version).toBe(6);

    // v2 columns now exist and pre-existing data survived
    const cols = db1
      .query('PRAGMA table_info(messages)')
      .all() as Array<{ name: string }>;
    expect(cols.map(c => c.name)).toContain('format_version');

    const msg = db1
      .query('SELECT text, format_version FROM messages')
      .get() as { text: string; format_version: number };
    expect(msg.text).toBe('pre-migration');
    expect(msg.format_version).toBe(1);

    db1.close();
  });

  test('initializeDatabase is idempotent at current version', () => {
    const db = new Database(':memory:');
    initializeDatabase(db);
    // Running again must not attempt migration 2 a second time
    // (which would fail: duplicate column)
    expect(() => initializeDatabase(db)).not.toThrow();
    db.close();
  });

  test('v4 CHECK constraints reject ambiguous permission rule shapes', () => {
    const db = new Database(':memory:');
    initializeDatabase(db);

    db.run(`INSERT INTO accounts (id) VALUES ('chk@example.com')`);

    // target_type='entity' requires target_entity_id
    expect(() => db.run(`
      INSERT INTO permissions (id, account_id, target_type, source_type, source_account_id, action)
      VALUES ('r1', 'chk@example.com', 'entity', 'account', 'chk@example.com', 'deny')
    `)).toThrow();

    // target_type='all' must not carry target_entity_id
    expect(() => db.run(`
      INSERT INTO permissions (id, account_id, target_type, target_entity_id, source_type, source_account_id, action)
      VALUES ('r2', 'chk@example.com', 'all', 'bogus', 'account', 'chk@example.com', 'deny')
    `)).toThrow();

    // source_type='entity' must not carry source_account_id
    expect(() => db.run(`
      INSERT INTO permissions (id, account_id, target_type, source_type, source_account_id, action)
      VALUES ('r3', 'chk@example.com', 'all', 'entity', 'chk@example.com', 'deny')
    `)).toThrow();

    db.close();
  });

  test('v3 database with ambiguous permission rows upgrades to v4 with normalization', () => {
    // Simulate a v3 database (post-migration-3) holding an ambiguous row:
    // target_type='all' but with target_entity_id set (possible pre-v4)
    const db = new Database(':memory:');
    db.exec('PRAGMA foreign_keys = ON');
    db.exec(`
      CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at TEXT DEFAULT (datetime('now')));
      CREATE TABLE accounts (id TEXT PRIMARY KEY, display_name TEXT, created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now')));
      CREATE TABLE entities (
        id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        type TEXT NOT NULL, display_name TEXT, capabilities TEXT DEFAULT '{}',
        location_server TEXT, public_key TEXT NOT NULL,
        status TEXT DEFAULT 'offline', created_at TEXT DEFAULT (datetime('now')), last_seen TEXT
      );
      CREATE TABLE grants (
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
      );
      CREATE TABLE permissions (
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
      );
      INSERT INTO schema_version (version) VALUES (3);
      INSERT INTO accounts (id) VALUES ('up@example.com');
      INSERT INTO entities (id, account_id, type, public_key) VALUES ('up@up@example.com', 'up@example.com', 'agent', 'pk');
      -- ambiguous row: all-target with stray entity id + account-source with stray entity id
      INSERT INTO permissions (id, account_id, target_type, target_entity_id, source_type, source_entity_id, source_account_id, action)
      VALUES ('amb', 'up@example.com', 'all', 'up@up@example.com', 'account', 'up@up@example.com', 'up@example.com', 'deny');
    `);

    initializeDatabase(db);

    const version = db
      .query('SELECT MAX(version) as version FROM schema_version')
      .get() as { version: number };
    expect(version.version).toBe(6);

    // The ambiguous row survived, normalized: target_entity_id and
    // source_entity_id stripped per the rule shape
    const row = db
      .query('SELECT target_entity_id, source_entity_id, source_account_id, action FROM permissions WHERE id = ?')
      .get('amb') as any;
    expect(row.target_entity_id).toBeNull();
    expect(row.source_entity_id).toBeNull();
    expect(row.source_account_id).toBe('up@example.com');
    expect(row.action).toBe('deny');

    db.close();
  });

  test('v5 database upgrades to v6, binding columns added and legacy rows left unbound', () => {
    const db = new Database(':memory:');
    db.exec(`
      CREATE TABLE accounts (
        id TEXT PRIMARY KEY,
        display_name TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now'))
      );
      CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at TEXT DEFAULT (datetime('now')));
      INSERT INTO schema_version (version) VALUES (5);
      INSERT INTO accounts (id, display_name) VALUES ('legacy@example.com', 'Legacy');
    `);

    initializeDatabase(db);

    const version = db
      .query('SELECT MAX(version) as version FROM schema_version')
      .get() as { version: number };
    expect(version.version).toBe(6);

    const cols = db.query('PRAGMA table_info(accounts)').all() as { name: string }[];
    const names = cols.map((c) => c.name);
    expect(names).toContain('provider');
    expect(names).toContain('provider_account_id');

    // The pre-existing row survives and is unbound — it adopts a provider on
    // its next authenticated login rather than being deleted or guessed at.
    const legacy = db
      .query('SELECT display_name, provider, provider_account_id FROM accounts WHERE id = ?')
      .get('legacy@example.com') as any;
    expect(legacy.display_name).toBe('Legacy');
    expect(legacy.provider).toBeNull();
    expect(legacy.provider_account_id).toBeNull();

    db.close();
  });

  test('v6 unique index rejects a second account for the same provider identity', () => {
    const db = new Database(':memory:');
    initializeDatabase(db);

    db.run(
      `INSERT INTO accounts (id, provider, provider_account_id) VALUES (?, 'google', 'sub-1')`,
      ['first@example.com']
    );

    // One provider identity must map to exactly one account, or the takeover
    // the binding exists to prevent reopens by a different route.
    expect(() =>
      db.run(
        `INSERT INTO accounts (id, provider, provider_account_id) VALUES (?, 'google', 'sub-1')`,
        ['second@example.com']
      )
    ).toThrow();

    db.close();
  });

  test('v6 unique index still allows many unbound legacy accounts', () => {
    const db = new Database(':memory:');
    initializeDatabase(db);

    // The index is partial (WHERE provider IS NOT NULL). Without that clause a
    // second pre-v6 row would collide and block the upgrade path.
    db.run(`INSERT INTO accounts (id) VALUES ('a@example.com')`);
    db.run(`INSERT INTO accounts (id) VALUES ('b@example.com')`);

    const count = db.query('SELECT COUNT(*) c FROM accounts WHERE provider IS NULL').get() as {
      c: number;
    };
    expect(count.c).toBe(2);

    db.close();
  });
});
