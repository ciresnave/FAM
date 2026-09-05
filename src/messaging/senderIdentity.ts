// Which key does a recipient verify a sender's signature against?
//
// ─────────────────────────────────────────────────────────────────────────────
// ⚠️ UNTIL NOW: THE SERVER'S. FAM never holds an X25519 private half, so
// confidentiality from the relay is genuine by construction — but the relay
// still SERVES the identity key a recipient checks signatures with. The
// guarantee was "the relay cannot read your mail", never "the relay cannot tell
// you the wrong sender".
// ─────────────────────────────────────────────────────────────────────────────
//
// The voucher chain replaces that key with one signed by the account holder,
// whose key lives in their own forge repository. This module decides, for one
// sender, which key may be used — or that none may be.
//
// It is a PURE FUNCTION over records that someone else fetched. The transport
// belongs to the caller; the decision belongs here, so the CLI and the MCP
// adapter cannot answer it differently.

import { resolveEntityKey, type SignedVoucher, type SignedRevocation } from '../crypto/voucher';

export interface SenderIdentityInput {
  entityId: string;
  /** The identity key the SERVER supplied, or null if it offered none. */
  serverSuppliedKey: string | null;
  /**
   * The account holder's public key, fetched from their forge and pinned.
   *
   * Null when it could not be obtained — no anchor published, network failure,
   * or a pin awaiting confirmation. Null is a real state and produces
   * `unvouched`, never a silent pass.
   */
  accountPublicKey: string | null;
  records: Array<SignedVoucher | SignedRevocation>;
  /** Explicit rather than `new Date()`: a clock read inside is untestable. */
  now?: Date;
}

export type SenderIdentity =
  /** A chain resolved and agrees with the server. Relay-independent. */
  | { kind: 'vouched'; publicKey: string }
  /**
   * No chain. The server's key, exactly as before — **the status quo, labelled**.
   *
   * ⚠️ NOT A DOWNGRADE. Every entity is in this state today; there is no
   * verified state being fallen back FROM. The caller should say so rather than
   * treat it as equivalent to `vouched`.
   */
  | { kind: 'unvouched'; publicKey: string }
  /**
   * Do not verify against anything.
   *
   * ⚠️ CARRIES NO KEY, DELIBERATELY. A refusal that still returned one would be
   * used by a caller that forgot to check `kind` — the same reason
   * `prepareSealedDirect` cannot return an unsealed message.
   */
  | { kind: 'refused'; reason: string };

export async function resolveSenderIdentity(
  input: SenderIdentityInput
): Promise<SenderIdentity> {
  // No anchor means no chain to check. This is the ordinary state today, and
  // the server's key is what would have been used anyway.
  if (!input.accountPublicKey) {
    return unvouchedOrRefused(input, 'no account key is published for this sender');
  }

  const resolution = await resolveEntityKey(
    input.accountPublicKey,
    input.entityId,
    input.records,
    input.now ?? new Date()
  );

  switch (resolution.status) {
    case 'valid':
      // ⚠️ DISAGREEMENT IS THE ATTACK, NOT AN ERROR CONDITION. The account
      // holder vouched for one key and the relay served another. Silently
      // preferring the vouched one would be defensible AND would discard the
      // only evidence that a substitution was attempted — the recipient would
      // never learn their relay had tried.
      if (input.serverSuppliedKey && resolution.entityPublicKey !== input.serverSuppliedKey) {
        return {
          kind: 'refused',
          reason:
            `The key ${input.entityId}'s account vouched for and the key this server served ` +
            `for them DIFFER. Nothing is shown. This is what a substituted sender key looks ` +
            `like from here, and it is the reason the voucher chain exists — treat it as a ` +
            `report about the relay, not about the sender.`,
        };
      }
      return { kind: 'vouched', publicKey: resolution.entityPublicKey };

    case 'revoked':
      return {
        kind: 'refused',
        reason:
          `${input.entityId}'s account has REVOKED the key this message would be checked ` +
          `against. Nothing is shown. The holder withdrew it deliberately.`,
      };

    case 'expired':
      // Distinct from revoked on purpose: the holder did not withdraw it, and a
      // relay withholding a fresh voucher is exactly what this looks like from
      // the recipient's side. Reporting it as revoked would accuse the holder.
      return {
        kind: 'refused',
        reason:
          `The voucher for ${input.entityId} has EXPIRED, so their key can no longer be ` +
          `confirmed as current. Nothing is shown. This is not a revocation — it can also ` +
          `mean a fresh voucher exists and is not reaching you.`,
      };

    case 'unknown':
      // An anchor exists but no verifiable record does. Records the account
      // holder did not sign were discarded before ranking, so a relay cannot
      // manufacture a chain — it can only fail to provide one.
      return unvouchedOrRefused(input, 'no verifiable voucher exists for this sender');
  }
}

/**
 * The server's key, or a refusal when there is not one either.
 *
 * ⚠️ AN EMPTY KEY MUST NEVER BE RETURNED. It would sail into the verifier and
 * fail exactly like a wrong key, reporting a genuine message as an unverifiable
 * one — the accusation-from-an-absence defect, one layer down.
 */
function unvouchedOrRefused(input: SenderIdentityInput, why: string): SenderIdentity {
  if (!input.serverSuppliedKey) {
    return {
      kind: 'refused',
      reason:
        `No key is known for ${input.entityId} — ${why}, and this server offered none ` +
        `either. Who wrote this cannot be established, which is NOT the same as the ` +
        `message being forged.`,
    };
  }

  return { kind: 'unvouched', publicKey: input.serverSuppliedKey };
}
