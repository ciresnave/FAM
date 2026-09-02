// Voucher Repository — storing account-signed entity/key bindings.
//
// ─────────────────────────────────────────────────────────────────────────────
// ⚠️ THIS REPOSITORY DOES NOT VERIFY, AND THAT IS DELIBERATE.
//
// It looks like an omission. It is the anchor argument: FAM cannot verify a
// voucher without the account public key, and it must never hold one — the
// whole point is that the account key comes from the holder's own forge repo,
// somewhere the relay cannot write. A server that "helpfully" verified would
// need a key it should not have, and a peer that trusted the server's
// verification would be back to trusting the relay.
//
// So storage accepts a well-formed record and THE RECIPIENT VERIFIES. A garbage
// record is stored and then refused by every reader, which is the correct
// division of labour: the relay is transport.
// ─────────────────────────────────────────────────────────────────────────────
//
// ⚠️ WHAT THE RELAY CAN STILL DO IS WITHHOLD. A server that does not return a
// revocation leaves a peer trusting a key that was revoked, and NO SIGNATURE
// CHECK DETECTS AN OMISSION. Ordering is handled — `resolveEntityKey` is
// order-independent — but absence cannot be, by any purely local check. Short
// validity, a transparency log, or fetching from the holder's repo would close
// it; none is built. This reduces the relay from FORGER to CENSOR.

import { Database } from 'bun:sqlite';
import type { SignedVoucher, SignedRevocation } from '../../crypto/voucher';
import { ValidationError } from '../../types/errors';

export type VoucherRecord = SignedVoucher | SignedRevocation;

export class VoucherRepository {
  constructor(private db: Database) {}

  /**
   * Store a record.
   *
   * IDEMPOTENT ON THE SIGNATURE, which is the natural identity: two records
   * carrying the same signature over the same bytes ARE the same record, so
   * re-publishing must not accumulate duplicates.
   *
   * ⚠️ But two DIFFERENT records at the same sequence are both kept. The server
   * cannot judge between two validly-signed records, and `resolveEntityKey`
   * already breaks that tie deterministically. Rejecting the second would make
   * the server pick a winner by insert order — the exact defect fixed in
   * `b139e3b`, moved down a layer where it would be harder to see.
   */
  store(record: VoucherRecord): void {
    if (typeof record?.signature !== 'string' || record.signature === '') {
      throw new ValidationError('A voucher record must carry a signature.');
    }
    if (typeof record.entity !== 'string' || typeof record.account !== 'string') {
      throw new ValidationError('A voucher record must name an account and an entity.');
    }
    if (typeof record.sequence !== 'number') {
      throw new ValidationError('A voucher record must carry a numeric sequence.');
    }

    const kind = 'revokedAt' in record ? 'revocation' : 'voucher';

    this.db
      .prepare(
        `INSERT OR IGNORE INTO vouchers
           (signature, account_id, entity_id, kind, sequence, record)
         VALUES (?, ?, ?, ?, ?, ?)`
      )
      .run(
        record.signature,
        record.account,
        record.entity,
        kind,
        record.sequence,
        // ⚠️ STORED VERBATIM, and here is the PRECISE reason — an earlier
        // version of this comment overstated it.
        //
        // The signature is over `canonicalVoucherBytes`, which reads NAMED
        // FIELDS. So JSON key order does NOT matter: reordering keys survives
        // verification, and claiming otherwise would have sent someone chasing
        // a property that is not load-bearing.
        //
        // What DOES matter is every field VALUE arriving back unchanged. Trim a
        // string, reformat a number, coerce `sequence` to `"1"`, and the record
        // stops verifying — silently, for every future reader, with nothing
        // failing until someone tries to trust it. `JSON.stringify` of the
        // record as given is the cheapest way to guarantee that, and it costs
        // nothing to also preserve key order.
        JSON.stringify(record)
      );
  }

  /**
   * Every stored record for an entity.
   *
   * The WHOLE set, deliberately: resolution depends on which record ranks
   * highest, so a partial set can only produce a stale answer — and a stale
   * answer here means trusting a key that was rotated or revoked.
   */
  listForEntity(entityId: string): VoucherRecord[] {
    const rows = this.db
      .prepare('SELECT record FROM vouchers WHERE entity_id = ? ORDER BY sequence ASC')
      .all(entityId) as Array<{ record: string }>;

    return rows.map((r) => JSON.parse(r.record) as VoucherRecord);
  }

  /** Every stored record issued by an account, across its entities. */
  listForAccount(accountId: string): VoucherRecord[] {
    const rows = this.db
      .prepare('SELECT record FROM vouchers WHERE account_id = ? ORDER BY sequence ASC')
      .all(accountId) as Array<{ record: string }>;

    return rows.map((r) => JSON.parse(r.record) as VoucherRecord);
  }
}
