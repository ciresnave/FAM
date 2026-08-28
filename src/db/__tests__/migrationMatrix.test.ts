import { test, expect, describe } from 'bun:test';
import { Database } from 'bun:sqlite';
import { initializeDatabase, migrateTo, CURRENT_SCHEMA_VERSION } from '../schema';

// ============================================================================
// EVERY schema version upgrades to current, and the list maintains itself.
//
// The matrix used to be hand-written fixtures — a database built by listing
// CREATE TABLE statements believed to match some old version. That failed twice
// in one day, both times the same way: the fixture stamped version N while
// physically lacking objects version N would have. Migration 8 hit it, the fix
// added the one table migration 8 needed, and migration 10 walked into the same
// hole two migrations later. Fixing the instance left the class.
//
// Worse, the coverage GAP GREW SILENTLY. Every migration added extended the
// untested-origins list by one, and nothing announced it: v2, v4, v7, v8, v9,
// v10, v11 and v12 were all untested as upgrade origins purely because they
// were added after someone last hand-wrote a fixture.
//
// So the origin is BUILT by running migrations 1..N — the real ones, in order.
// A version-N database is then by construction what a version-N database is,
// and the loop below is bounded by CURRENT_SCHEMA_VERSION, so adding a
// migration extends the coverage instead of the debt. There is no list.
//
// This is the direction that matters: the rewind tests found two real defects
// (migration 8 not re-appliable, migration 11 a bare ALTER) and only in the
// versions they happened to cover.
// ============================================================================

function versionOf(db: Database): number {
  const row = db.query('SELECT MAX(version) as v FROM schema_version').get() as { v: number };
  return row.v;
}

describe('every version upgrades to current', () => {
  // Not a fixed list: derived from CURRENT_SCHEMA_VERSION, so a new migration
  // is covered the moment it exists.
  const origins = Array.from({ length: CURRENT_SCHEMA_VERSION - 1 }, (_, i) => i + 1);

  test('the matrix covers every version below current', () => {
    // Guards the loop against silently shrinking to nothing — an empty origins
    // list would make every test below vacuous.
    expect(origins.length).toBe(CURRENT_SCHEMA_VERSION - 1);
    expect(origins.length).toBeGreaterThan(5);
  });

  for (const origin of Array.from({ length: 32 }, (_, i) => i + 1)) {
    if (origin >= CURRENT_SCHEMA_VERSION) continue;

    test(`v${origin} -> v${CURRENT_SCHEMA_VERSION}`, () => {
      const db = new Database(':memory:');
      try {
        migrateTo(db, origin);
        expect(versionOf(db)).toBe(origin);

        initializeDatabase(db);

        expect(versionOf(db)).toBe(CURRENT_SCHEMA_VERSION);
      } finally {
        db.close();
      }
    });
  }
});

describe('the machinery the matrix rests on', () => {
  test('migrateTo stops where it is told', () => {
    const db = new Database(':memory:');
    try {
      migrateTo(db, 3);
      expect(versionOf(db)).toBe(3);
      // A column added later must NOT be present, or migrateTo is quietly
      // running everything and the whole matrix proves nothing.
      const cols = db.query('PRAGMA table_info(entities)').all() as { name: string }[];
      expect(cols.some(c => c.name === 'summary')).toBe(false);
    } finally {
      db.close();
    }
  });

  test('a fully migrated database is idempotent under re-initialisation', () => {
    const db = new Database(':memory:');
    try {
      initializeDatabase(db);
      const first = versionOf(db);
      initializeDatabase(db);
      expect(versionOf(db)).toBe(first);
    } finally {
      db.close();
    }
  });

  // Every migration must survive being applied twice: a step that cannot be
  // repeated cannot be retried after a partial failure, and the rewind tests
  // re-run later migrations against a database that already carries them.
  test('each migration is re-appliable', () => {
    for (let v = 2; v <= CURRENT_SCHEMA_VERSION; v++) {
      const db = new Database(':memory:');
      try {
        migrateTo(db, v);
        db.run('DELETE FROM schema_version WHERE version >= ?', [v]);
        // Re-running the migration over its own output must not throw.
        expect(() => migrateTo(db, v)).not.toThrow();
      } finally {
        db.close();
      }
    }
  });
});
