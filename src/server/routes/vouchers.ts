// Voucher routes — publishing and fetching account-signed key bindings.
//
// ─────────────────────────────────────────────────────────────────────────────
// ⚠️ THESE ROUTES DO NOT VERIFY SIGNATURES, AND THAT IS THE ANCHOR ARGUMENT
// RATHER THAN AN OMISSION.
//
// FAM cannot verify a voucher without the account public key, and it must never
// hold one: the anchor is the holder's own forge repository, which the relay
// cannot write to. A server that "helpfully" verified would need a key it
// should not have — and a peer that trusted the server's verification would be
// back to trusting the relay, which is the entire thing the voucher chain
// defends against.
//
// So publishing accepts a well-formed record and THE RECIPIENT VERIFIES. A
// forged record is stored and then refused by every reader, which is the
// correct division of labour: the relay is transport.
// ─────────────────────────────────────────────────────────────────────────────
//
// ⚠️ WHAT THE RELAY CAN STILL DO IS WITHHOLD. A server that does not return a
// revocation leaves a peer trusting a revoked key, and NO SIGNATURE CHECK
// DETECTS AN OMISSION — signature checks are existence proofs and have nothing
// to say about absence. Voucher expiry bounds it (a withheld revocation only
// works until the current voucher lapses); it does not remove it.

import type { DatabaseContext } from '../../db/transaction';
import type { Route } from './index';
import { requireEntitySession, requireAccountAuth } from '../middleware/auth';
import { NotFoundError, ForbiddenError, ValidationError } from '../../types/errors';
import type { SignedVoucher, SignedRevocation } from '../../crypto/voucher';

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

const RECORD_FIELDS = {
  version: 'number',
  account: 'string',
  entity: 'string',
  sequence: 'number',
  signature: 'string',
} as const;

const VOUCHER_ONLY = {
  entityPublicKey: 'string',
  issuedAt: 'string',
  expiresAt: 'string',
} as const;

/**
 * Reject anything that is not a well-formed record.
 *
 * Shape only — never the signature. "The server cannot verify it" is not "the
 * server accepts anything": an unparseable record is undeliverable at every
 * reader forever, so it is refused at the door rather than stored as data
 * nobody can use.
 */
function assertRecordShape(record: unknown): asserts record is SignedVoucher | SignedRevocation {
  const bad: string[] = [];
  const obj = record as Record<string, unknown> | null;

  if (obj == null || typeof obj !== 'object') {
    throw new ValidationError('record must be an object.');
  }

  for (const [field, expected] of Object.entries(RECORD_FIELDS)) {
    if (typeof obj[field] !== expected) bad.push(field);
  }

  // A revocation carries `revokedAt`; a voucher carries the binding fields.
  // Checked as two shapes rather than one union of optionals, because
  // "whichever fields happen to be present" is how a record that is neither
  // gets stored as both.
  if ('revokedAt' in obj) {
    if (typeof obj.revokedAt !== 'string') bad.push('revokedAt');
  } else {
    for (const [field, expected] of Object.entries(VOUCHER_ONLY)) {
      if (typeof obj[field] !== expected) bad.push(field);
    }
  }

  if (bad.length > 0) {
    throw new ValidationError(
      `Malformed voucher record: missing or wrong type: ${bad.join(', ')}.`
    );
  }
}

export function voucherRoutes(ctx: DatabaseContext): Route[] {
  return [
    // POST /vouchers/publish
    // Publish a voucher or revocation. Account-authenticated.
    {
      method: 'POST',
      pattern: '/vouchers/publish',
      handler: async (req) => {
        const { accountId, body } = await requireAccountAuth(ctx, req);
        const { record } = body;

        if (record === undefined || record === null) {
          return json({ error: 'record is required' }, 400);
        }

        assertRecordShape(record);

        // ⚠️ THE LOAD-BEARING AUTHORIZATION CHECK. Without it any account could
        // publish records naming any other account. A peer holding the right
        // account key would reject them on the signature — but a peer that has
        // NOT yet obtained that key could be seeded with plausible-looking
        // history, and the cost of refusing here is one comparison.
        //
        // The account comes from the SESSION, never from the record: a record
        // that could name its own publisher would make this check circular.
        if (record.account !== accountId) {
          throw new ForbiddenError(
            `A voucher may only be published for your own account. ` +
              `This record names "${record.account}".`
          );
        }

        // Idempotent on the signature, so a client retrying after a timeout is
        // not punished for succeeding twice.
        ctx.vouchers.store(record);

        return json({ stored: true }, 201);
      },
    },

    // POST /vouchers/list
    // Every stored record for an entity. Entity session required.
    {
      method: 'POST',
      pattern: '/vouchers/list',
      handler: async (req) => {
        const { entityId, body } = await requireEntitySession(ctx, req);
        // ⚠️ NOT `entity_id`. That field name is already claimed by
        // `requireEntitySession`, which reads a body `entity_id` as a
        // REDUNDANT ASSERTION OF WHO THE CALLER IS and rejects a mismatch with
        // 401. This route needs the opposite meaning — who is being ASKED
        // ABOUT — and reusing the name made every query about another entity
        // fail authentication instead of answering.
        //
        // Two meanings for one field, and the middleware's wins because it runs
        // first. Renamed rather than special-cased: a route that needed the
        // middleware to make an exception for it would be a second answer to
        // "who is the caller".
        const { subject_entity_id } = body;

        if (!subject_entity_id) {
          return json({ error: 'subject_entity_id is required' }, 400);
        }

        // ⚠️ VISIBILITY IS INHERITED FROM THE DIRECTORY, not a second answer to
        // "may A see B". A voucher discloses that an entity exists and which
        // key it uses — for an entity already in your directory that is nothing
        // new, and for one outside it, this would be an enumeration oracle.
        //
        // Same 404 for "not visible" and "does not exist", as everywhere else
        // in this codebase: a caller that could tell them apart holds a probe.
        const caller = ctx.entities.getById(entityId)!;
        const visible = ctx.entities
          .getDirectoryForAccount(caller.account_id)
          .some((e) => e.id === subject_entity_id);

        if (!visible) {
          throw new NotFoundError('Entity', subject_entity_id);
        }

        // ⚠️ THE WHOLE SET, never "the current one". Resolution depends on which
        // record ranks highest and a partial set can only produce a STALE
        // answer — which here means trusting a key that was rotated or revoked.
        // A route that returned "the current voucher" would be making the
        // resolution decision itself, and that decision is the recipient's.
        return json({ records: ctx.vouchers.listForEntity(subject_entity_id) });
      },
    },
  ];
}
