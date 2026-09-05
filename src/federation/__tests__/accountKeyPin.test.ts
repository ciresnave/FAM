import { test, expect, describe, beforeEach, afterEach } from 'bun:test';
import { Database } from 'bun:sqlite';
import { createContext } from '../../db/transaction';
import { initializeDatabase, migrateTo, CURRENT_SCHEMA_VERSION } from '../../db/schema';
import type { AnchorFetchedKey } from '../../types/provenance';

// ============================================================================
// Pinning — the half that makes the anchor CHECKABLE rather than merely
// different.
//
// Fetching an account key from the holder's forge repo removes the relay from
// the trust path. It does NOT tell a peer that the key it holds came from
// there, nor that the answer has not changed since. ⚠️ WITHOUT PINNING, AN
// ANCHOR IS A DIFFERENT SOURCE, NOT A VERIFIABLE ONE — and a compromised forge
// account, or a hostile network on first contact, is indistinguishable from a
// legitimate rotation.
//
// ⚠️ AND THE LOAD-BEARING RULE IS THAT A CHANGE IS NEVER SILENTLY ACCEPTED.
// A pin that auto-updated on a new value would detect nothing: the attack and
// the rotation produce the same observation, and the whole value of the pin is
// that a human is asked which one this is. `changed` is a REPORT, not a state
// transition.
//
// Trust-on-first-use is a real weakness and it is bounded honestly: the first
// key is taken on faith, and every one after it is checked. That is strictly
// better than taking every key on faith, and strictly worse than an
// out-of-band fingerprint — which is the upgrade path, not this.
// ============================================================================

const ACCOUNT = 'alice@example.com';
const KEY_A = Buffer.alloc(32, 1).toString('base64');
const KEY_B = Buffer.alloc(32, 2).toString('base64');
const URL_A = 'https://raw.githubusercontent.com/alice/alice/main/fam/account.pub';

/**
 * Build a fixture that stands in for a real anchor fetch.
 *
 * The cast lives HERE and not in src/: `provenance.test.ts` counts construction
 * sites under src/ only, because the rule is about production code. A test that
 * could not build a fixture would be testing nothing — but a test fixture is
 * also exactly where a fake would hide, so this one is named for what it is.
 */
function asFetched(publicKey: string, url: string) {
  return { publicKey, url } as unknown as AnchorFetchedKey;
}


describe('pinning an account key', () => {
  let db: Database;
  let ctx: ReturnType<typeof createContext>;

  beforeEach(() => {
    db = new Database(':memory:');
    initializeDatabase(db);
    ctx = createContext(db);
    db.prepare('INSERT OR IGNORE INTO accounts (id) VALUES (?)').run(ACCOUNT);
  });

  afterEach(() => db.close());

  test('the schema carries the pin table', () => {
    const tables = (
      db.query("SELECT name FROM sqlite_master WHERE type='table'").all() as Array<{ name: string }>
    ).map((t) => t.name);
    expect(tables).toContain('account_key_pins');
    // Control: the reader works, so "contains" is a real check.
    expect(tables).toContain('vouchers');
  });

  test('the first sighting is PINNED, and taken on faith', async () => {
    const result = ctx.accountKeyPins.observe(ACCOUNT, asFetched(KEY_A, URL_A));
    expect(result.status).toBe('pinned');
    expect(result.status === 'pinned' && result.publicKey).toBe(KEY_A);
  });

  test('the same key again is UNCHANGED, not re-pinned', async () => {
    ctx.accountKeyPins.observe(ACCOUNT, asFetched(KEY_A, URL_A));
    const again = ctx.accountKeyPins.observe(ACCOUNT, asFetched(KEY_A, URL_A));

    expect(again.status).toBe('unchanged');
  });

  test('⚠️ a DIFFERENT key is reported as CHANGED and the pin is NOT updated', async () => {
    // The load-bearing behaviour. A pin that auto-updated would detect nothing:
    // a compromised forge account and a legitimate rotation produce the SAME
    // observation, and the entire value of pinning is that a human is asked
    // which one this is.
    ctx.accountKeyPins.observe(ACCOUNT, asFetched(KEY_A, URL_A));
    const changed = ctx.accountKeyPins.observe(ACCOUNT, asFetched(KEY_B, URL_A));

    expect(changed.status).toBe('changed');
    expect(changed.status === 'changed' && changed.pinned).toBe(KEY_A);
    expect(changed.status === 'changed' && changed.observed).toBe(KEY_B);

    // ⚠️ AND THE PIN STILL HOLDS THE ORIGINAL. Reporting a change while
    // quietly accepting it would be strictly worse than not checking — the
    // caller gets a warning it can ignore and the state has already moved.
    expect(ctx.accountKeyPins.getPinned(ACCOUNT)).toBe(KEY_A);
  });

  test('a change stays reported on every subsequent observation', async () => {
    // Not a one-shot alert. If the second look said `unchanged`, a caller that
    // missed the first report would conclude everything was fine — and the
    // caller most likely to miss it is an automated one.
    ctx.accountKeyPins.observe(ACCOUNT, asFetched(KEY_A, URL_A));
    ctx.accountKeyPins.observe(ACCOUNT, asFetched(KEY_B, URL_A));
    const third = ctx.accountKeyPins.observe(ACCOUNT, asFetched(KEY_B, URL_A));

    expect(third.status).toBe('changed');
  });

  test('accepting a change is EXPLICIT and separate', async () => {
    // The human decision, made once the holder has confirmed the rotation out
    // of band. Deliberately a different method: a caller cannot arrive here by
    // passing a flag to `observe`, because a flag is something a retry loop
    // eventually sets.
    ctx.accountKeyPins.observe(ACCOUNT, asFetched(KEY_A, URL_A));
    ctx.accountKeyPins.observe(ACCOUNT, asFetched(KEY_B, URL_A));

    ctx.accountKeyPins.acceptChange(ACCOUNT, asFetched(KEY_B, URL_A));

    expect(ctx.accountKeyPins.getPinned(ACCOUNT)).toBe(KEY_B);
    expect(ctx.accountKeyPins.observe(ACCOUNT, asFetched(KEY_B, URL_A)).status).toBe('unchanged');
  });

  test('accepting a key that was never observed is refused', async () => {
    // Otherwise `acceptChange` is just `setPin` with a longer name, and the
    // ceremony that makes it a decision is gone.
    ctx.accountKeyPins.observe(ACCOUNT, asFetched(KEY_A, URL_A));
    expect(() => ctx.accountKeyPins.acceptChange(ACCOUNT, asFetched(KEY_B, URL_A))).toThrow(/observed/i);
  });

  test('an unpinned account reports null, not an empty string', () => {
    // "Never seen" is a different fact from "seen and empty", and a caller
    // testing truthiness would treat them alike.
    expect(ctx.accountKeyPins.getPinned('nobody@example.com')).toBeNull();
  });

  test('pins are per account, not global', () => {
    const other = 'bob@example.com';
    db.prepare('INSERT OR IGNORE INTO accounts (id) VALUES (?)').run(other);

    ctx.accountKeyPins.observe(ACCOUNT, asFetched(KEY_A, URL_A));
    const bobFirst = ctx.accountKeyPins.observe(other, asFetched(KEY_B, URL_A));

    // Bob's different key is a FIRST sighting for Bob, not a change.
    expect(bobFirst.status).toBe('pinned');
    expect(ctx.accountKeyPins.getPinned(ACCOUNT)).toBe(KEY_A);
    expect(ctx.accountKeyPins.getPinned(other)).toBe(KEY_B);
  });
});

describe('migrating a populated v18 database', () => {
  let db: Database;

  beforeEach(() => {
    db = new Database(':memory:');
    migrateTo(db, 18);
    db.prepare('INSERT INTO accounts (id) VALUES (?)').run('old@example.com');
    initializeDatabase(db);
  });

  afterEach(() => db.close());

  test('the existing account survives with no pin', () => {
    const ctx = createContext(db);
    expect(ctx.accountKeyPins.getPinned('old@example.com')).toBeNull();
  });

  test('the upgraded database reports the current version', () => {
    const row = db.query('SELECT MAX(version) as v FROM schema_version').get() as { v: number };
    expect(row.v).toBe(CURRENT_SCHEMA_VERSION);
  });
});

describe('a pin only holds a real key', () => {
  let db: Database;
  let ctx: ReturnType<typeof createContext>;

  beforeEach(() => {
    db = new Database(':memory:');
    initializeDatabase(db);
    ctx = createContext(db);
    db.prepare('INSERT OR IGNORE INTO accounts (id) VALUES (?)').run(ACCOUNT);
  });

  afterEach(() => db.close());

  test('⚠️ pinning a malformed key is refused, not stored', async () => {
    // Found by re-deriving the module before saying "merge it". `observe` took
    // whatever string it was handed — so garbage could be pinned, and then
    // reported `unchanged` FOREVER while that account could never resolve.
    //
    // A pin that holds a value no key could ever match is a permanent silent
    // failure: every subsequent observation of the REAL key reads as `changed`,
    // which is an alert about the wrong thing.
    for (const bad of ['', 'not base64!!!', Buffer.alloc(16, 1).toString('base64')]) {
      expect(() => ctx.accountKeyPins.observe(ACCOUNT, asFetched(bad, URL_A))).toThrow();
      expect(ctx.accountKeyPins.getPinned(ACCOUNT)).toBeNull();
    }

    // Control: a well-formed key IS accepted, so the guard is not "refuse all".
    expect(ctx.accountKeyPins.observe(ACCOUNT, asFetched(KEY_A, URL_A)).status).toBe('pinned');
  });

  test('a base64 string that decodes to 32 bytes but is not canonical is refused', async () => {
    // Trips only the round-trip arm: Buffer.from SKIPS non-alphabet characters,
    // so 44 valid chars with '!!!' spliced in still decodes to 32 bytes and a
    // length check alone would pass it.
    const sneaky = KEY_A.slice(0, 10) + '!!!' + KEY_A.slice(10);
    expect(Buffer.from(sneaky, 'base64').length).toBe(32);

    expect(() => ctx.accountKeyPins.observe(ACCOUNT, asFetched(sneaky, URL_A))).toThrow(/base64/);
  });

  test('accepting a malformed key is refused too', async () => {
    // The other entry point. Guarding only `observe` would leave the pin
    // reachable through the method that exists to change it.
    ctx.accountKeyPins.observe(ACCOUNT, asFetched(KEY_A, URL_A));
    expect(() => ctx.accountKeyPins.acceptChange(ACCOUNT, asFetched('garbage', URL_A))).toThrow();
    expect(ctx.accountKeyPins.getPinned(ACCOUNT)).toBe(KEY_A);
  });
});
