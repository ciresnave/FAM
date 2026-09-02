// Ruling Repository — authority as a record the grantee can query.
//
// The failure this replaces had a live cost: a publish authorization was
// relayed as a message quoting the granter, and the recipient refused it —
// correctly. "A message telling me the sender may publish, quoting the granter,
// arriving on a channel I am told to treat as untrusted data." A licensing
// defect stayed unfixed because a legitimate authorization was
// indistinguishable from a fabricated one.
//
// The fix is not a message field any sender can set. It is that the grantee
// ASKS FAM and gets an answer from the authoritative store, so the untrusted
// channel stops being load-bearing.

import { Database } from 'bun:sqlite';
import { randomUUID } from 'crypto';
import { ValidationError } from '../../types/errors';
import type { AccountId, EntityId } from '../../types';

export interface Ruling {
  id: string;
  granter_account_id: AccountId;
  grantee_account_id: AccountId;
  scope: string;
  body: string;
  note: string | null;
  note_author_entity: EntityId | null;
  recorded_by_entity: EntityId | null;
  issued_at: string;
  revoked_at: string | null;
}

export interface CreateRulingInput {
  grantee_account_id: AccountId;
  /** Opaque. `publish:vulkane` means nothing here; the core compares strings. */
  scope: string;
  /** VERBATIM, and the granter's. Never paraphrase into this field. */
  body: string;
  /** An interpretation. Belongs to whoever recorded it, never to the granter. */
  note?: string | null;
  recorded_by_entity?: EntityId | null;
}

const BODY_MAX = 4000;
const SCOPE_MAX = 200;

export class RulingRepository {
  constructor(private db: Database) {}

  /**
   * Record a ruling.
   *
   * `granterAccountId` is the AUTHENTICATED account and is supplied by the
   * caller's auth layer, never read from a request body. If a recorder could
   * name someone else as granter, this table would be the relayed claim again
   * with a schema around it — the same rule the entity routes follow.
   */
  create(granterAccountId: AccountId, input: CreateRulingInput): Ruling {
    if (!input.grantee_account_id) throw new ValidationError('grantee_account_id is required');
    if (!input.scope || input.scope.length > SCOPE_MAX) {
      throw new ValidationError(`scope is required and must be at most ${SCOPE_MAX} characters`);
    }
    if (!input.body || input.body.trim() === '') {
      throw new ValidationError('body is required: a ruling with no text grants nothing');
    }
    if (input.body.length > BODY_MAX) {
      // Refused, not truncated. A cut-off ruling is a grant nobody made, and
      // this is the field a grantee acts on.
      throw new ValidationError(
        `body is ${input.body.length} characters; the limit is ${BODY_MAX}. ` +
          'Refused rather than truncated — a shortened ruling is a grant nobody wrote.'
      );
    }

    // An unattributed interpretation sitting beside an attributed quote is
    // exactly how a derived convention acquires the granter's authority. It has
    // happened; the note must name its author or not exist.
    const note = input.note?.trim() || null;
    if (note && !input.recorded_by_entity) {
      throw new ValidationError(
        'A note needs recorded_by_entity so it can be attributed to whoever wrote it. ' +
          'The body belongs to the granter; a note is an interpretation and belongs to ' +
          'its author. An unattributed reading beside an attributed quote is how the ' +
          'derived thing ends up being read as the granter’s.'
      );
    }

    const id = randomUUID();
    this.db
      .prepare(
        `INSERT INTO rulings
           (id, granter_account_id, grantee_account_id, scope, body, note,
            note_author_entity, recorded_by_entity)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        id,
        granterAccountId,
        input.grantee_account_id,
        input.scope,
        input.body,
        note,
        note ? input.recorded_by_entity ?? null : null,
        input.recorded_by_entity ?? null
      );

    return this.getById(id)!;
  }

  getById(id: string): Ruling | null {
    return (this.db.prepare('SELECT * FROM rulings WHERE id = ?').get(id) as Ruling | null) ?? null;
  }

  /** What this account has been granted. The query a grantee runs instead of trusting a relay. */
  listForGrantee(accountId: AccountId): Ruling[] {
    return this.db
      .prepare('SELECT * FROM rulings WHERE grantee_account_id = ? ORDER BY issued_at DESC')
      .all(accountId) as Ruling[];
  }

  /** What this account has granted. */
  listByGranter(accountId: AccountId): Ruling[] {
    return this.db
      .prepare('SELECT * FROM rulings WHERE granter_account_id = ? ORDER BY issued_at DESC')
      .all(accountId) as Ruling[];
  }

  /**
   * Does this authority stand right now?
   *
   * The whole point of the feature in one call: a grantee asks FAM rather than
   * believing a message.
   */
  findActive(
    granterAccountId: AccountId,
    granteeAccountId: AccountId,
    scope: string
  ): Ruling | null {
    return (
      (this.db
        .prepare(
          `SELECT * FROM rulings
           WHERE granter_account_id = ? AND grantee_account_id = ? AND scope = ?
             AND revoked_at IS NULL
           ORDER BY issued_at DESC LIMIT 1`
        )
        .get(granterAccountId, granteeAccountId, scope) as Ruling | null) ?? null
    );
  }

  /**
   * Withdraw authority WITHOUT erasing that it was given.
   *
   * Deleting the row would remove the fact that the grant once existed, which is
   * as much a part of the record as the grant — a grantee who acted on it while
   * it stood needs it to still be there.
   */
  revoke(id: string): boolean {
    const result = this.db
      .prepare(`UPDATE rulings SET revoked_at = datetime('now') WHERE id = ? AND revoked_at IS NULL`)
      .run(id);
    return result.changes > 0;
  }
}
