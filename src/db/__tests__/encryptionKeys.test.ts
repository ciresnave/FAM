import { test, expect, describe, beforeAll } from 'bun:test';
import { Database } from 'bun:sqlite';
import { getDatabaseContext } from '../index';
import { initializeDatabase, migrateTo, CURRENT_SCHEMA_VERSION } from '../schema';
import type { DatabaseContext } from '../transaction';

// ============================================================================
// Migration 17 — entity encryption keys, and the sealed-message discriminator.
//
// THE COLUMN CANNOT BE BACKFILLED, AND THAT IS THE DESIGN, NOT A LIMITATION.
// An entity's X25519 private key belongs to the entity. FAM generating one on
// its behalf would mean FAM could read the entity's mail, which is the exact
// property sealing exists to remove. So `encryption_public_key` is NULL for
// every entity that has not supplied one, and NULL is a real state with a real
// meaning: THIS ENTITY CANNOT RECEIVE SEALED MESSAGES YET.
//
// That makes rollout per-recipient rather than global, which in turn creates
// the failure this file is mostly about:
//
// ⚠️ A SENDER MUST NEVER SILENTLY FALL BACK TO UNSEALED. "Encrypted unless it
// wasn't" is indistinguishable from "encrypted" at every call site that does
// not check, and the one time it matters is the one time nobody checked. So
// `messages.sealed` records what actually happened to each row, the default is
// 0 rather than NULL, and every pre-migration message becomes 0 — which is
// TRUE of them: they were not sealed.
//
// The discriminator is a column rather than an inference from the text,
// because "does this look like an envelope?" is a guess and a guess that
// answers wrong hands back ciphertext as a message body. That has already
// happened once here: MessageEncryptionMismatchError exists because turning
// the at-rest flag OFF over encrypted rows is SILENT and returns the raw
// envelope as text.
// ============================================================================

const ACCOUNT = 'sealing@example.com';
const WITH_KEY = `haskey@${ACCOUNT}`;
const WITHOUT_KEY = `nokey@${ACCOUNT}`;

// A real X25519 public key is 32 bytes; base64 of 32 bytes is 44 characters.
const X25519_PUBLIC = Buffer.alloc(32, 7).toString('base64');

let ctx: DatabaseContext;

beforeAll(() => {
  ctx = getDatabaseContext();
  ctx.db.prepare('INSERT OR IGNORE INTO accounts (id) VALUES (?)').run(ACCOUNT);
  for (const id of [WITH_KEY, WITHOUT_KEY]) {
    ctx.db
      .prepare(
        `INSERT OR IGNORE INTO entities (id, account_id, type, public_key, capabilities)
         VALUES (?, ?, 'agent', 'pk', '{"can_send":true}')`
      )
      .run(id, ACCOUNT);
  }
});

describe('the schema carries an encryption key that FAM cannot invent', () => {
  test('the version advanced', () => {
    expect(CURRENT_SCHEMA_VERSION).toBe(17);
  });

  test('an entity that has never supplied a key reads NULL, not empty string', () => {
    // NULL and '' are different claims. An empty string is a key that is
    // present and useless; NULL is the absence of one. Collapsing them makes
    // "never supplied" indistinguishable from "supplied something broken".
    const row = ctx.db
      .prepare('SELECT encryption_public_key FROM entities WHERE id = ?')
      .get(WITHOUT_KEY) as { encryption_public_key: string | null };

    expect(row.encryption_public_key).toBeNull();
  });

  test('a supplied key round trips', () => {
    ctx.entities.setEncryptionKey(WITH_KEY, X25519_PUBLIC);

    const row = ctx.db
      .prepare('SELECT encryption_public_key FROM entities WHERE id = ?')
      .get(WITH_KEY) as { encryption_public_key: string | null };
    expect(row.encryption_public_key).toBe(X25519_PUBLIC);
  });

  test('a key of the wrong size is refused', () => {
    // An X25519 public key is exactly 32 bytes. Accepting anything else stores
    // a value that fails much later, inside a crypto call, on someone else's
    // message.
    expect(() => ctx.entities.setEncryptionKey(WITH_KEY, 'dG9vIHNob3J0')).toThrow(/32 bytes/);
  });

  test('a key that is not valid base64 is refused, even at the right length', () => {
    // ⚠️ THIS TEST WAS MASKED WHEN FIRST WRITTEN, and the masking is the same
    // shape as the sealing mutants one increment earlier.
    //
    // It used `'!!! not base64 !!!'`, which Buffer.from decodes to SIX bytes.
    // So it was rejected by the LENGTH check, not the base64 check, and
    // deleting the base64 check entirely left the test passing. Validation is a
    // disjunction — refused if malformed OR wrong length — and a case that
    // trips both arms cannot tell you either one works.
    //
    // This input trips exactly one. Buffer.from silently SKIPS characters
    // outside the base64 alphabet rather than throwing, so the '!!!' vanishes
    // and the remainder decodes to a full 32 bytes: the length arm passes and
    // only the round-trip comparison can reject it.
    const valid = Buffer.alloc(32, 3).toString('base64');
    const sneaky = valid.slice(0, 10) + '!!!' + valid.slice(10);

    expect(Buffer.from(sneaky, 'base64').length).toBe(32); // the length arm is satisfied
    expect(() => ctx.entities.setEncryptionKey(WITH_KEY, sneaky)).toThrow(/base64/);
  });
});

describe('whether a recipient can receive sealed mail is a question with an answer', () => {
  // Rather than a null check repeated at every call site. The point is that a
  // sender is FORCED to have an answer before it can choose a path, so the
  // fallback to unsealed is a decision somewhere rather than a default
  // everywhere.
  test('an entity with a key can', () => {
    ctx.entities.setEncryptionKey(WITH_KEY, X25519_PUBLIC);
    expect(ctx.entities.canReceiveSealed(WITH_KEY)).toBe(true);
  });

  test('an entity without one cannot', () => {
    expect(ctx.entities.canReceiveSealed(WITHOUT_KEY)).toBe(false);
  });

  test('an entity that does not exist cannot, and does not throw', () => {
    // Same answer as "exists but has no key", deliberately. A caller that could
    // tell them apart would hold an existence oracle for entities in other
    // accounts, which the rest of this codebase refuses to provide.
    expect(ctx.entities.canReceiveSealed(`ghost@${ACCOUNT}`)).toBe(false);
  });
});

describe('migrating a populated v16 database', () => {
  // The matrix test proves the migration RUNS from every origin. This proves it
  // preserves what was there and that the new columns mean the right thing for
  // rows that predate them — which a schema-shape assertion cannot see.
  let db: Database;

  beforeAll(() => {
    db = new Database(':memory:');
    migrateTo(db, 16);

    db.prepare('INSERT INTO accounts (id) VALUES (?)').run('old@example.com');
    db.prepare(
      `INSERT INTO entities (id, account_id, type, public_key)
       VALUES (?, ?, 'agent', 'pk')`
    ).run('legacy@old@example.com', 'old@example.com');
    db.prepare(
      `INSERT INTO messages (from_entity, to_entity, text)
       VALUES (?, ?, ?)`
    ).run('legacy@old@example.com', 'legacy@old@example.com', 'sent before sealing existed');

    initializeDatabase(db);
  });

  test('the existing entity survives with no encryption key', () => {
    const row = db
      .prepare('SELECT id, public_key, encryption_public_key FROM entities WHERE id = ?')
      .get('legacy@old@example.com') as {
      public_key: string;
      encryption_public_key: string | null;
    };

    expect(row.public_key).toBe('pk'); // identity key untouched
    expect(row.encryption_public_key).toBeNull();
  });

  test('a message written before sealing existed is marked NOT sealed', () => {
    // 0 rather than NULL, and it is the true answer rather than a placeholder:
    // that message was not sealed. A NULL here would mean "unknown", and a
    // reader would have to guess — which is how ciphertext gets handed back as
    // a message body.
    const row = db
      .prepare('SELECT text, sealed FROM messages WHERE from_entity = ?')
      .get('legacy@old@example.com') as { text: string; sealed: number };

    expect(row.text).toBe('sent before sealing existed');
    expect(row.sealed).toBe(0);
  });

  test('the upgraded database reports the current version', () => {
    const row = db.query('SELECT MAX(version) as v FROM schema_version').get() as { v: number };
    expect(row.v).toBe(CURRENT_SCHEMA_VERSION);
  });
});
