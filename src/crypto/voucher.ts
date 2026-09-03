// Vouchers — an account key binding an entity id to an entity public key.
//
// ─────────────────────────────────────────────────────────────────────────────
// ⚠️ WHY THIS EXISTS, IN ONE LINE: EVERY SIGNATURE CHECK IN FAM TODAY
// TERMINATES AT A VALUE THE SERVER CONTROLS.
//
// `entities.public_key` is a column in the server's own database, served to
// peers via `/entities/list` and verified against by the server itself
// (`messageSend.ts` calls `verifyEnvelope(sender.public_key, …)`). A malicious
// home server needs nobody's private key: it publishes its own public key for
// an entity and forges freely. The victim's key is untouched, perfectly safe,
// and irrelevant — nobody was ever checking against it.
//
// An INVALID key would fail verification and be noticed. A VALID key the server
// substituted is undetectable. That is the whole problem.
// ─────────────────────────────────────────────────────────────────────────────
//
// ⚠️ AND THE WRONG VERSION OF THIS FIX LOOKS FINISHED. A voucher chain rooted
// in an account key that FAM also serves passes every signature check, reads as
// a completed federation trust model, and defends against nothing the relay
// does — more signatures, same trust root. **VOUCHERS WITHOUT AN ANCHOR THE
// RELAY CANNOT WRITE TO SOUND LIKE A FIX AND ARE NOT ONE.**
//
// So `verifyVoucher` and `resolveEntityKey` take the account public key as a
// PARAMETER the caller must supply. Nothing here fetches one, and FAM must
// never serve one: the anchor is the account holder's own forge repository,
// which the relay cannot write to. See `DESIGN-FEDERATION.md`.
//
// ⚠️ THE ANCHOR IS NOT YET VERIFIABLE, only different. A peer that obtains an
// account key from a repo has removed the relay from the trust path, but cannot
// yet tell that the key it holds CAME from there, nor notice when the answer
// changes. Pinning-on-first-use with change alerts, a transparency log, or a
// fingerprint the holder publishes out-of-band all close that; none is built.
// Recorded so "we use git" is not mistaken for "it is checkable".

import { sign, verify } from './keys';

const VOUCHER_VERSION = 1;

// ⚠️ DISTINCT DOMAINS, NOT DECORATION. Without them a signature over one record
// could be presented as the other, and the two say OPPOSITE things about
// whether an entity may be trusted.
const VOUCHER_DOMAIN = 'fam-voucher-v1';
const REVOCATION_DOMAIN = 'fam-revocation-v1';

export interface VoucherFields {
  /** Account id that owns the entity. */
  account: string;
  /** Entity id being vouched for. */
  entity: string;
  /** Base64 Ed25519 public key this voucher binds to `entity`. */
  entityPublicKey: string;
  issuedAt: string;
  /**
   * When this voucher stops being evidence. REQUIRED — no optional, no default.
   *
   * ⚠️ THIS PUTS A CLOCK ON THE ONE ATTACK SIGNATURES CANNOT SEE. A relay that
   * withholds a revocation leaves a peer trusting a revoked key, and no
   * signature check detects an omission: SIGNATURE CHECKS ARE EXISTENCE PROOFS
   * AND HAVE NOTHING TO SAY ABOUT ABSENCE. Expiry does not remove the censor —
   * it bounds them. Withholding works only until the current voucher lapses,
   * after which the relay must produce a fresh one it cannot forge. An
   * undetectable indefinite attack becomes a bounded one.
   *
   * Optional would defeat it: a voucher with no expiry is one the relay can
   * serve forever, and "expiring unless the issuer omitted it" is the caller's
   * choice to disable the bound without noticing.
   */
  expiresAt: string;
  /**
   * Monotonic per entity. Resolution is BY SEQUENCE, never by arrival order —
   * a relay that cannot forge can still choose what to show, and replaying a
   * superseded record is the cheapest attack it has.
   */
  sequence: number;
}

export interface SignedVoucher extends VoucherFields {
  version: number;
  /** Ed25519 signature by the ACCOUNT key, base64. */
  signature: string;
}

export interface RevocationFields {
  account: string;
  entity: string;
  revokedAt: string;
  sequence: number;
}

export interface SignedRevocation extends RevocationFields {
  version: number;
  signature: string;
}

export type EntityKeyResolution =
  | { status: 'valid'; entityPublicKey: string; sequence: number }
  | { status: 'revoked'; sequence: number }
  /**
   * The winning voucher has lapsed.
   *
   * ⚠️ DISTINCT FROM BOTH NEIGHBOURS, and the distinction is the signal. Not
   * `revoked` — the holder did not withdraw it. Not `unknown` — a voucher
   * exists and was seen. Collapsing it into `unknown` would hide that the peer
   * IS BEING KEPT ON STALE DATA, which is exactly what withholding produces
   * and the only trace it leaves.
   */
  | { status: 'expired'; sequence: number }
  /**
   * No verifiable record. Deliberately DISTINCT from `revoked`: "I hold no
   * voucher for this entity" and "this entity was revoked" are different facts,
   * and collapsing them either trusts an unvouched key or reports a revocation
   * that never happened.
   */
  | { status: 'unknown' };

/**
 * The exact bytes a voucher signature covers.
 *
 * ⚠️ EVERY FIELD LENGTH-PREFIXED. Unprefixed, `account "ab@x" + entity "c@y"`
 * and `account "ab@xc" + entity "@y"` serialise identically, so one signature
 * would cover two different bindings. Here that splice is not hypothetical:
 * AN ENTITY ID CONTAINS ITS ACCOUNT ID, so the two fields are adjacent strings
 * that share a boundary by construction.
 */
export function canonicalVoucherBytes(fields: VoucherFields & { version: number }): Uint8Array {
  return lengthPrefixed([
    VOUCHER_DOMAIN,
    String(fields.version),
    fields.account,
    fields.entity,
    fields.entityPublicKey,
    fields.issuedAt,
    fields.expiresAt,
    String(fields.sequence),
  ]);
}

export function canonicalRevocationBytes(
  fields: RevocationFields & { version: number }
): Uint8Array {
  return lengthPrefixed([
    REVOCATION_DOMAIN,
    String(fields.version),
    fields.account,
    fields.entity,
    fields.revokedAt,
    String(fields.sequence),
  ]);
}

/** Sign a voucher with the ACCOUNT private key. Never an entity key. */
export async function signVoucher(
  accountPrivateKeyBase64: string,
  fields: VoucherFields
): Promise<SignedVoucher> {
  const version = VOUCHER_VERSION;
  const signature = await sign(
    canonicalVoucherBytes({ version, ...fields }),
    accountPrivateKeyBase64
  );
  return { version, ...fields, signature };
}

export async function signRevocation(
  accountPrivateKeyBase64: string,
  fields: RevocationFields
): Promise<SignedRevocation> {
  const version = VOUCHER_VERSION;
  const signature = await sign(
    canonicalRevocationBytes({ version, ...fields }),
    accountPrivateKeyBase64
  );
  return { version, ...fields, signature };
}

/**
 * Check a voucher against an account public key THE CALLER SUPPLIES.
 *
 * There is deliberately no lookup here. A function that could fetch the account
 * key would be fetching it from somewhere, and the only somewhere FAM knows is
 * the relay — which is the party this defends against.
 */
export async function verifyVoucher(
  accountPublicKeyBase64: string,
  voucher: SignedVoucher
): Promise<boolean> {
  if (!isWellFormedVoucher(voucher)) return false;
  try {
    return await verify(
      canonicalVoucherBytes(voucher),
      voucher.signature,
      accountPublicKeyBase64
    );
  } catch {
    return false;
  }
}

export async function verifyRevocation(
  accountPublicKeyBase64: string,
  revocation: SignedRevocation
): Promise<boolean> {
  if (!isWellFormedRevocation(revocation)) return false;
  try {
    return await verify(
      canonicalRevocationBytes(revocation),
      revocation.signature,
      accountPublicKeyBase64
    );
  } catch {
    return false;
  }
}

/**
 * Decide the current key for `entity` from a bag of records.
 *
 * ⚠️ UNVERIFIABLE RECORDS ARE DISCARDED BEFORE ANY COMPARISON, not ranked
 * lower. A relay can inject a forgery with sequence 999; if unverified records
 * participated in ranking at all it would win, and even losing it would have
 * influenced the outcome. Verify first, then compare.
 *
 * ⚠️ AND RESOLUTION IS BY SEQUENCE, NEVER BY ORDER OF ARRIVAL. Replaying a
 * superseded voucher after a revocation is the cheapest attack available to a
 * relay that cannot forge, and every record involved is perfectly valid.
 */
export async function resolveEntityKey(
  accountPublicKeyBase64: string,
  entity: string,
  records: Array<SignedVoucher | SignedRevocation>,
  /** Explicit rather than `new Date()`: a clock read inside is untestable. */
  now: Date = new Date()
): Promise<EntityKeyResolution> {
  const candidates = await verifiedCandidates(accountPublicKeyBase64, entity, records);
  if (candidates.length === 0) return { status: 'unknown' };

  const winner = candidates.reduce((best, next) => (outranks(next, best) ? next : best));

  if (winner.kind === 'revocation') return { status: 'revoked', sequence: winner.sequence };

  // ⚠️ EXPIRY IS CHECKED ON THE WINNER, AFTER RANKING, AND NEVER FALLS BACK.
  //
  // Reverting to the newest still-valid record would let a rotation be UNDONE
  // BY WAITING: let the new voucher lapse and the old key becomes current
  // again — and the holder may have rotated precisely because the old key was
  // compromised. A lapsed winner means lapsed, not "try the runner-up".
  // `!(expiry > now)` rather than `expiry <= now`. `Date.parse` returns NaN on
  // anything it cannot read, and EVERY comparison with NaN is false — including
  // the negation — so the direction you write the test in picks the failure
  // mode outright:
  //
  //     if (parsed <= now)    NaN -> does NOT expire   FAILS OPEN
  //     if (!(parsed > now))  NaN -> DOES expire       FAILS CLOSED
  //
  // ⚠️ AND THIS FORM IS CURRENTLY UNREACHABLE FOR THE NaN CASE, MEASURED, not
  // assumed. `verifiedCandidates` calls `verifyVoucher`, which now rejects an
  // unparseable expiry, so no candidate reaching here can carry one — reverting
  // this line to the fails-open form leaves all 25 tests passing.
  //
  // Kept anyway, and NOT claimed as independently tested. It costs nothing, and
  // if the verification guard is ever relaxed or a path appears that does not
  // go through `verifyVoucher`, the difference between these two forms is
  // whether that mistake grants permanence or revokes it. The safe direction is
  // free; the unsafe one is only safe while something else holds.
  const expiry = Date.parse(winner.expiresAt);
  if (!(expiry > now.getTime())) {
    return { status: 'expired', sequence: winner.sequence };
  }

  return { status: 'valid', entityPublicKey: winner.entityPublicKey, sequence: winner.sequence };
}

type Candidate =
  | { kind: 'revocation'; sequence: number; signature: string }
  | {
      kind: 'voucher';
      sequence: number;
      signature: string;
      entityPublicKey: string;
      expiresAt: string;
    };

/**
 * Records for `entity` whose signature verifies under the account key.
 *
 * Split from ranking on purpose. Verification and precedence are two decisions,
 * and interleaving them is how an unverified record ends up participating in a
 * comparison — losing is not enough, because a record that participates has
 * already influenced the outcome.
 */
async function verifiedCandidates(
  accountPublicKeyBase64: string,
  entity: string,
  records: Array<SignedVoucher | SignedRevocation>
): Promise<Candidate[]> {
  const out: Candidate[] = [];

  for (const record of records) {
    if (record.entity !== entity) continue;

    if ('revokedAt' in record) {
      if (await verifyRevocation(accountPublicKeyBase64, record)) {
        out.push({ kind: 'revocation', sequence: record.sequence, signature: record.signature });
      }
    } else if (await verifyVoucher(accountPublicKeyBase64, record)) {
      out.push({
        kind: 'voucher',
        sequence: record.sequence,
        signature: record.signature,
        entityPublicKey: record.entityPublicKey,
        expiresAt: record.expiresAt,
      });
    }
  }

  return out;
}

/**
 * A TOTAL order over candidates, so the result cannot depend on list order.
 *
 * ⚠️ THIS EXISTS BECAUSE THE FIRST VERSION COMPARED `sequence <= best.sequence`,
 * which made EQUAL sequences resolve by array position — AND THE RELAY CONTROLS
 * THAT POSITION, because the relay hands the peer the record list. It cannot
 * forge either record. It does not need to: if a holder ever issues a voucher
 * and a revocation at the same sequence, the relay would choose whether the
 * entity is live or revoked.
 *
 * Three rules, in order, and every pair of distinct candidates is separated by
 * one of them:
 *
 *   1. higher sequence wins            — the ordinary case
 *   2. at a tie, REVOCATION wins       — fail closed. A revoked entity treated
 *                                        as live is silent and dangerous; a live
 *                                        entity treated as revoked is loud and
 *                                        recoverable.
 *   3. at a tie of the same kind,      — arbitrary but DETERMINISTIC and
 *      the larger signature wins         relay-independent, so two colliding
 *                                        vouchers still resolve the same way for
 *                                        every peer. Which one wins does not
 *                                        matter; that they agree does.
 */
function outranks(x: Candidate, y: Candidate): boolean {
  if (x.sequence !== y.sequence) return x.sequence > y.sequence;
  if (x.kind !== y.kind) return x.kind === 'revocation';
  return x.signature > y.signature;
}

// ============================================================================
// Internals
// ============================================================================

function isWellFormedVoucher(v: SignedVoucher): boolean {
  return (
    v != null &&
    typeof v.version === 'number' &&
    typeof v.account === 'string' &&
    typeof v.entity === 'string' &&
    typeof v.entityPublicKey === 'string' &&
    typeof v.issuedAt === 'string' &&
    typeof v.expiresAt === 'string' &&
    // ⚠️ AND IT MUST PARSE. `typeof === 'string'` accepts "soon", which
    // `Date.parse` turns into NaN — and NaN loses every comparison, so an
    // unparseable expiry silently becomes an eternal one. Refused at
    // verification so it cannot be published; `resolveEntityKey` guards the
    // same hole independently, for a record that arrived some other way.
    // ⚠️ AND IT MUST PARSE. `typeof === 'string'` accepts "soon", which
    // `Date.parse` turns into NaN — and NaN loses every comparison, so an
    // unparseable expiry silently becomes an eternal one. Refused at
    // verification so it cannot be published; `resolveEntityKey` guards the
    // same hole independently, for a record that arrived some other way.
    !Number.isNaN(Date.parse(v.expiresAt)) &&
    typeof v.sequence === 'number' &&
    typeof v.signature === 'string' &&
    // A voucher has no `revokedAt`. Checked so a revocation handed to
    // `verifyVoucher` is refused on SHAPE as well as on domain separation —
    // two independent reasons, because this pair says opposite things.
    !('revokedAt' in v)
  );
}

function isWellFormedRevocation(r: SignedRevocation): boolean {
  return (
    r != null &&
    typeof r.version === 'number' &&
    typeof r.account === 'string' &&
    typeof r.entity === 'string' &&
    typeof r.revokedAt === 'string' &&
    typeof r.sequence === 'number' &&
    typeof r.signature === 'string' &&
    !('entityPublicKey' in r)
  );
}

/** Shared with the message envelope's encoder for the same reason it exists there. */
function lengthPrefixed(parts: string[]): Uint8Array {
  const encoder = new TextEncoder();
  const encoded = parts.map((p) => encoder.encode(p));
  const total = encoded.reduce((n, p) => n + 4 + p.length, 0);

  const out = new Uint8Array(new ArrayBuffer(total));
  const view = new DataView(out.buffer);
  let offset = 0;
  for (const part of encoded) {
    view.setUint32(offset, part.length, false);
    offset += 4;
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
