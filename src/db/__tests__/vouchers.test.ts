import { test, expect, describe, beforeEach, afterEach } from 'bun:test';
import { Database } from 'bun:sqlite';
import { createContext } from '../transaction';
import { initializeDatabase, migrateTo, CURRENT_SCHEMA_VERSION } from '../schema';
import { generateKeyPair, bufferToBase64 } from '../../crypto/keys';
import { signVoucher, signRevocation, resolveEntityKey } from '../../crypto/voucher';

// ============================================================================
// Storing vouchers — and why it is safe for the RELAY to hold them.
//
// A voucher is self-authenticating under the account key. FAM can store one,
// serve one, and cannot alter one without breaking a signature it cannot
// produce. THAT IS THE POINT OF THE WHOLE DESIGN: the relay is allowed to be
// the transport for these records precisely because it is not trusted with
// them.
//
// ⚠️ WHAT THE RELAY CAN STILL DO, stated here because storage is where someone
// would assume the problem is solved: IT CAN WITHHOLD. A server that simply
// does not return a revocation leaves a peer trusting a key that was revoked,
// and no signature check detects an omission. Ordering is handled —
// `resolveEntityKey` is order-independent — but ABSENCE is not, and cannot be
// by any purely local check.
//
// Closing it needs something that makes absence visible: short voucher
// validity so a stale set expires, a transparency log, or the peer fetching
// from the holder's own repo rather than from the relay. None is built. This
// module therefore reduces the relay from FORGER to CENSOR, which is a real
// improvement and not the whole job.
//
// ⚠️ AND THE SERVER IS NOT AN ARBITER. Two validly-signed records at the same
// sequence are BOTH stored: the server cannot judge between them, and
// resolution already handles the tie deterministically. A uniqueness
// constraint here would make the server pick a winner by insert order — which
// is the exact defect just fixed in `resolveEntityKey`, moved down a layer.
// ============================================================================

const ACCOUNT = 'alice@example.com';
const ENTITY = `agent@${ACCOUNT}`;

describe('voucher storage', () => {
  let db: Database;
  let ctx: ReturnType<typeof createContext>;
  let acct: { publicKey: string; privateKey: string };

  beforeEach(async () => {
    db = new Database(':memory:');
    initializeDatabase(db);
    ctx = createContext(db);

    const k = await generateKeyPair();
    acct = { publicKey: bufferToBase64(k.publicKey), privateKey: bufferToBase64(k.privateKey) };

    db.prepare('INSERT OR IGNORE INTO accounts (id) VALUES (?)').run(ACCOUNT);
  });

  afterEach(() => db.close());

  async function voucher(sequence: number, entityPublicKey?: string) {
    return signVoucher(acct.privateKey, {
      account: ACCOUNT,
      entity: ENTITY,
      entityPublicKey: entityPublicKey ?? bufferToBase64((await generateKeyPair()).publicKey),
      issuedAt: '2026-09-02T20:00:00.000Z',
      sequence,
    });
  }

  test('the schema version advanced', () => {
    expect(CURRENT_SCHEMA_VERSION).toBe(18);
  });

  test('a voucher round trips field for field', async () => {
    const v = await voucher(1);
    ctx.vouchers.store(v);

    const [back] = ctx.vouchers.listForEntity(ENTITY);
    expect(back).toEqual(v);
  });

  test('a field VALUE altered in storage stops it verifying', async () => {
    // ⚠️ THIS TEST REPLACES AN OVERSTATED CLAIM OF MINE. I had written that
    // "any normalisation — reordered keys, a trimmed string, a reformatted
    // number — destroys verifiability". Reordered keys do NOT: the signature is
    // over `canonicalVoucherBytes`, which reads NAMED FIELDS, so key order
    // survives. Asserting otherwise would have sent someone defending a
    // property that is not load-bearing.
    //
    // What actually matters is field VALUES surviving unchanged, and this
    // demonstrates the direction that bites: a trimmed or reformatted value
    // still round-trips as an object and still fails every reader.
    const v = await voucher(1);
    ctx.vouchers.store({ ...v, issuedAt: v.issuedAt + ' ' });

    const resolved = await resolveEntityKey(
      acct.publicKey,
      ENTITY,
      ctx.vouchers.listForEntity(ENTITY)
    );
    expect(resolved.status).toBe('unknown');

    // ⚠️ THE CONTROL HAD TO CLEAR THE TABLE, AND FINDING OUT WHY IS THE SECOND
    // HALF OF THIS TEST. Storing the original after the altered one is a NO-OP:
    // they carry the SAME signature, the signature is the primary key, and the
    // insert is OR IGNORE. So an altered record OCCUPIES THE ORIGINAL'S
    // IDENTITY and the true one can never be stored alongside it.
    //
    // That is correct — a signature IS the identity, and holding two records
    // claiming one signature would be incoherent — but it means corruption here
    // is not repairable by re-publishing. The holder must issue a new record at
    // a higher sequence. Worth knowing before someone tries "just re-send it".
    ctx.db.prepare('DELETE FROM vouchers').run();

    ctx.vouchers.store(v);
    const withOriginal = await resolveEntityKey(
      acct.publicKey,
      ENTITY,
      ctx.vouchers.listForEntity(ENTITY)
    );
    expect(withOriginal.status).toBe('valid');
  });

  test('what comes back out still verifies', async () => {
    // The assertion that a round-trip-equality test cannot make on its own: not
    // "the object looks the same" but "the crypto still accepts it".
    const v = await voucher(1);
    ctx.vouchers.store(v);

    const resolved = await resolveEntityKey(acct.publicKey, ENTITY, ctx.vouchers.listForEntity(ENTITY));
    expect(resolved.status).toBe('valid');
    expect(resolved.status === 'valid' && resolved.entityPublicKey).toBe(v.entityPublicKey);
  });

  test('a revocation round trips and resolves', async () => {
    ctx.vouchers.store(await voucher(1));
    ctx.vouchers.store(
      await signRevocation(acct.privateKey, {
        account: ACCOUNT,
        entity: ENTITY,
        revokedAt: '2026-09-02T21:00:00.000Z',
        sequence: 2,
      })
    );

    const resolved = await resolveEntityKey(acct.publicKey, ENTITY, ctx.vouchers.listForEntity(ENTITY));
    expect(resolved.status).toBe('revoked');
  });

  test('⚠️ TWO records at the same sequence are BOTH stored', async () => {
    // The server cannot judge between two validly-signed records, and
    // resolution already breaks the tie deterministically. A uniqueness
    // constraint on (entity, sequence) would make the server pick a winner BY
    // INSERT ORDER — the exact defect fixed in resolveEntityKey, moved down a
    // layer where it would be harder to see.
    const a = await voucher(5);
    const b = await voucher(5);
    ctx.vouchers.store(a);
    ctx.vouchers.store(b);

    expect(ctx.vouchers.listForEntity(ENTITY).length).toBe(2);
  });

  test('storing the same record twice is idempotent', async () => {
    // Distinct from the case above: the SAME record, not two different ones.
    // Re-publishing should not accumulate duplicates, and the signature is the
    // natural identity — two records with the same signature over the same
    // bytes ARE the same record.
    const v = await voucher(7);
    ctx.vouchers.store(v);
    ctx.vouchers.store(v);

    expect(ctx.vouchers.listForEntity(ENTITY).length).toBe(1);
  });

  test('records for other entities are not returned', async () => {
    const other = `someone-else@${ACCOUNT}`;
    ctx.vouchers.store(await voucher(1));
    ctx.vouchers.store(
      await signVoucher(acct.privateKey, {
        account: ACCOUNT,
        entity: other,
        entityPublicKey: bufferToBase64((await generateKeyPair()).publicKey),
        issuedAt: '2026-09-02T20:00:00.000Z',
        sequence: 1,
      })
    );

    const mine = ctx.vouchers.listForEntity(ENTITY);
    expect(mine.length).toBe(1);
    expect(mine[0]!.entity).toBe(ENTITY);
    // Control: the other record IS retrievable, so "not returned" is a filter
    // and not an empty table.
    expect(ctx.vouchers.listForEntity(other).length).toBe(1);
  });

  test('an unknown entity returns an empty list, not an error', async () => {
    expect(ctx.vouchers.listForEntity(`ghost@${ACCOUNT}`)).toEqual([]);
  });

  test('the server does NOT verify on the way in', async () => {
    // ⚠️ Deliberate, and it looks wrong at first glance. FAM cannot verify a
    // voucher without the account public key, and it must never hold one —
    // that is the entire anchor argument. A server that "helpfully" verified
    // would need a key it should not have, and a peer that trusted the server's
    // verification would be back to trusting the relay.
    //
    // So storage accepts a well-formed record and the RECIPIENT verifies. A
    // garbage record is stored and then fails at every reader, which is the
    // correct division: the relay is transport.
    const forged = { ...(await voucher(9)), signature: 'AAAA' };
    ctx.vouchers.store(forged);

    expect(ctx.vouchers.listForEntity(ENTITY).length).toBe(1);
    const resolved = await resolveEntityKey(acct.publicKey, ENTITY, ctx.vouchers.listForEntity(ENTITY));
    // Stored, and refused by the only party whose opinion counts.
    expect(resolved.status).toBe('unknown');
  });
});

describe('migrating a populated v17 database', () => {
  let db: Database;

  beforeEach(() => {
    db = new Database(':memory:');
    migrateTo(db, 17);
    db.prepare('INSERT INTO accounts (id) VALUES (?)').run('old@example.com');
    db.prepare(
      `INSERT INTO entities (id, account_id, type, public_key)
       VALUES (?, ?, 'agent', 'pk')`
    ).run('legacy@old@example.com', 'old@example.com');
    initializeDatabase(db);
  });

  afterEach(() => db.close());

  test('the existing entity survives and has no vouchers', () => {
    const row = db
      .prepare('SELECT id FROM entities WHERE id = ?')
      .get('legacy@old@example.com') as { id: string };
    expect(row.id).toBe('legacy@old@example.com');

    const count = db
      .prepare('SELECT COUNT(*) as n FROM vouchers')
      .get() as { n: number };
    expect(count.n).toBe(0);
  });

  test('the upgraded database reports the current version', () => {
    const row = db.query('SELECT MAX(version) as v FROM schema_version').get() as { v: number };
    expect(row.v).toBe(CURRENT_SCHEMA_VERSION);
  });
});
