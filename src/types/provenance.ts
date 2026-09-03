// Provenance brands — types that record WHERE a value came from, not just what
// shape it has.
//
// ─────────────────────────────────────────────────────────────────────────────
// ⚠️ WHY THIS EXISTS: TWICE IN ONE FEATURE'S LINEAGE A GUARD CHECKED A VALUE'S
// SHAPE AND NOT ITS ORIGIN.
//
//   `acceptChange` required only that a pin existed and differed, so any
//   well-formed key could be pinned — including one that had never been fetched
//   from anywhere.
//
//   `observe` took a bare string, so a relay-supplied key could be pinned and
//   would then report `unchanged` forever.
//
// Both were caught, both were fixed with a check, and BOTH FIXES WERE STILL
// SHAPE CHECKS. A well-formed key from the wrong source passes every one of
// them. The property that matters is not "is this 32 base64 bytes" but "did
// this come from the holder's anchor".
// ─────────────────────────────────────────────────────────────────────────────
//
// ⚠️ WHAT A BRAND ACTUALLY BUYS, STATED HONESTLY BECAUSE OVERSTATING IT WOULD
// BE THE EXACT DEFECT THIS FILE IS ABOUT.
//
// It is NOT unforgeable. `something as AnchorFetchedKey` compiles, and any
// caller determined to lie can write it. What it changes is the DEFAULT: the
// natural way to call `observe` is now to pass what a fetch returned, and
// supplying anything else requires an explicit, greppable cast that a reviewer
// sees as a claim rather than as ordinary code.
//
// The enforcement is not the type. It is `provenance.test.ts`, which COUNTS the
// construction sites and fails if a second appears — a step that executes,
// rather than a principle that has to be remembered. That distinction has been
// the only thing that reliably works.

/**
 * Type-only brand. There is no runtime value, so this cannot be constructed by
 * calling anything — only by a cast, and only one cast is permitted to exist.
 */
declare const ANCHOR_FETCHED: unique symbol;

/**
 * An account public key that was read from the holder's own forge repository.
 *
 * The ONLY sanctioned construction site is `fetchAccountKey` in
 * `src/federation/accountKey.ts`. A second one is a test failure, not a review
 * comment.
 */
export interface AnchorFetchedKey {
  readonly [ANCHOR_FETCHED]: true;
  /** Base64 raw Ed25519, already validated by the fetch. */
  readonly publicKey: string;
  /** Where it was read from. Part of what a holder needs to judge a change. */
  readonly url: string;
}
