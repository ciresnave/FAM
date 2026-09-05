// Account Key Pin Repository — trust-on-first-use with change detection.
//
// ─────────────────────────────────────────────────────────────────────────────
// ⚠️ THIS IS THE HALF THAT MAKES THE ANCHOR CHECKABLE RATHER THAN MERELY
// DIFFERENT.
//
// Fetching an account key from the holder's forge repository removes the RELAY
// from the trust path. It does not tell a peer that the key it holds CAME from
// there, nor that the answer has not changed since. Without a pin, an anchor is
// a different source, not a verifiable one — and a compromised forge account,
// or a hostile network on first contact, is indistinguishable from a legitimate
// rotation.
// ─────────────────────────────────────────────────────────────────────────────
//
// ⚠️ THE LOAD-BEARING RULE: `observe` NEVER UPDATES THE PIN. A pin that moved
// on a new value would detect nothing — the attack and the rotation produce the
// SAME observation, and the entire value of pinning is that a human is asked
// which one this is. `changed` is a REPORT, not a state transition.
//
// Trust-on-first-use is a real weakness and it is bounded honestly: the first
// key is taken on faith, and every one after it is checked. Strictly better
// than taking every key on faith; strictly worse than an out-of-band
// fingerprint, which is the upgrade path rather than this.

import { Database } from 'bun:sqlite';
import { ValidationError } from '../../types/errors';
import { assertRaw32ByteKey } from '../../types/validation';
import type { AnchorFetchedKey } from '../../types/provenance';

export type PinObservation =
  /** First sighting. Taken on faith — this is the trust-on-first-use step. */
  | { status: 'pinned'; publicKey: string }
  | { status: 'unchanged'; publicKey: string }
  /**
   * ⚠️ A REPORT, NOT A TRANSITION. The pin still holds `pinned` after this.
   * Reporting a change while quietly accepting it would be strictly worse than
   * not checking: the caller gets a warning it can ignore and the state has
   * already moved.
   */
  | { status: 'changed'; pinned: string; observed: string };

export class AccountKeyPinRepository {
  constructor(private db: Database) {}

  /**
   * Record what was seen, and say how it compares to what is pinned.
   *
   * Never writes over an existing pin. See the class note.
   */
  observe(accountId: string, fetched: AnchorFetchedKey): PinObservation {
    // The branded type is the point: a bare string cannot reach here, so the
    // ONLY thing that can be pinned is something fetchAccountKey produced.
    // Shape checks accept a well-formed key from any source; this accepts a key
    // from one source. See src/types/provenance.ts.
    const { publicKey, url } = fetched;

    // ⚠️ A PIN THAT HOLDS GARBAGE IS A PERMANENT SILENT FAILURE. Every
    // later observation of the REAL key would read as `changed` — an alert
    // about the wrong thing — and the account could never resolve. Guarded here
    // and in acceptChange, because guarding only one leaves the pin reachable
    // through the other.
    assertRaw32ByteKey(publicKey, {
      field: 'An account key being pinned',
      why: 'A pin is only as useful as the value in it.',
    });

    const existing = this.getPinned(accountId);

    if (existing === null) {
      this.db
        .prepare(
          `INSERT INTO account_key_pins (account_id, public_key, first_seen_url)
           VALUES (?, ?, ?)`
        )
        .run(accountId, publicKey, url);
      return { status: 'pinned', publicKey };
    }

    if (existing === publicKey) {
      return { status: 'unchanged', publicKey };
    }

    // Record WHAT was seen, without moving the pin. This is not a state
    // transition on the trust decision — it is evidence that `acceptChange`
    // later requires, so that accepting is bounded to keys actually observed
    // at the anchor rather than to any value a caller supplies.
    this.db
      .prepare(
        `UPDATE account_key_pins
         SET pending_public_key = ?, pending_seen_url = ?
         WHERE account_id = ?`
      )
      .run(publicKey, url, accountId);

    // ⚠️ Reported on EVERY subsequent observation, not once. A one-shot alert
    // means a caller that missed the first report concludes everything is fine
    // — and the caller most likely to miss it is an automated one.
    return { status: 'changed', pinned: existing, observed: publicKey };
  }

  /** The pinned key, or null if this account has never been observed. */
  getPinned(accountId: string): string | null {
    const row = this.db
      .prepare('SELECT public_key FROM account_key_pins WHERE account_id = ?')
      .get(accountId) as { public_key: string } | undefined;

    // null rather than '', because "never seen" and "seen and empty" are
    // different facts and a caller testing truthiness would treat them alike.
    return row?.public_key ?? null;
  }

  /**
   * Move the pin to a key whose change has been confirmed out of band.
   *
   * ⚠️ A SEPARATE METHOD, NOT A FLAG ON `observe`. A flag is something a retry
   * loop eventually sets and a caller eventually defaults; a distinct method
   * has to be reached for. The ceremony IS the safeguard — this is the point
   * where a human has checked with the holder that the rotation was theirs.
   */
  acceptChange(accountId: string, fetched: AnchorFetchedKey): void {
    const { publicKey, url } = fetched;

    assertRaw32ByteKey(publicKey, {
      field: 'An account key being accepted',
      why: 'A pin is only as useful as the value in it.',
    });

    const existing = this.getPinned(accountId);
    if (existing === null) {
      throw new ValidationError(
        `No pin exists for ${accountId}; there is no change to accept.`
      );
    }
    if (existing === publicKey) {
      throw new ValidationError(
        `The pinned key for ${accountId} is already this value; there is no change to accept.`
      );
    }

    // ⚠️ THE KEY MUST HAVE BEEN OBSERVED AT THE ANCHOR. Without this,
    // `acceptChange` is `setPin` with extra ceremony: a caller could pin a key
    // that never came from anywhere, which is the exact attack the pin exists
    // to stop, performed through the remedy for it.
    //
    // My first version checked only that a pin existed and differed, and the
    // test asserting this property failed against it. The test was right.
    const pending = this.db
      .prepare('SELECT pending_public_key FROM account_key_pins WHERE account_id = ?')
      .get(accountId) as { pending_public_key: string | null } | undefined;

    if (pending?.pending_public_key !== publicKey) {
      throw new ValidationError(
        `That key has not been observed at ${accountId}'s anchor. ` +
          `Only a key this server has actually fetched can be accepted.`
      );
    }

    this.db
      .prepare(
        `UPDATE account_key_pins
         SET public_key = ?, first_seen_url = ?, accepted_at = datetime('now'),
             pending_public_key = NULL, pending_seen_url = NULL
         WHERE account_id = ?`
      )
      .run(publicKey, url, accountId);
  }
}
