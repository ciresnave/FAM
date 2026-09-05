// Preparing an outgoing message — the one place that decides whether it seals.
//
// ─────────────────────────────────────────────────────────────────────────────
// ⚠️ THE CLI AND THE MCP ADAPTER BOTH SEND, AND THEY MUST NOT EACH DECIDE.
//
// "Can this recipient receive sealed mail?" answered in two places is two
// answers waiting to drift, and the drift is invisible in the direction that
// matters: one adapter quietly sending plaintext where the other seals. Same
// reasoning as the single session-authentication implementation, and the same
// reasoning that put enforcement in `MessageSendService` rather than in a route.
// ─────────────────────────────────────────────────────────────────────────────
//
// ⚠️ THERE IS NO PLAINTEXT FALLBACK IN HERE, DELIBERATELY. This returns either
// a sealed envelope or a REFUSAL carrying a reason. A helper that handed back
// "your message, unsealed" on the failure path would reinstate the silent
// downgrade one layer up — and the caller who forgot to check the flag is
// precisely the one who ships it. Sending plaintext must be a separate,
// named act at the call site, not a value this function can return.

import { seal } from './sealing';
import { signEnvelope, type SignedEnvelope } from './envelope';

export interface OutgoingInput {
  /** Sender entity id, `name@account`. */
  senderId: string;
  /** Base64 Ed25519 private key. Never leaves the caller's process. */
  senderIdentityPrivateKey: string;
  /** Recipient entity id, `name@account`. */
  recipientId: string;
  /**
   * The recipient's published X25519 public key, or null if they have none.
   *
   * ⚠️ NULL IS A REAL ANSWER AND MUST BE PASSED THROUGH AS ONE. A caller that
   * substitutes its own placeholder — '', a zero key, the identity key — turns
   * "cannot be sealed" into "sealed to something unopenable", and the failure
   * surfaces only when the recipient tries to read.
   */
  recipientEncryptionPublicKey: string | null;
  text: string;
  /** Per-sender counter. Replay protection lives on this. */
  sequence: number;
  /** Overridable only so tests can pin it; defaults to now. */
  sentAt?: string;
}

export type OutgoingDecision =
  | { sealed: true; envelope: SignedEnvelope }
  | { sealed: false; reason: string };

/**
 * Seal and sign a direct message, or refuse with a reason a person can act on.
 *
 * The refusal deliberately does NOT carry the message text: a reason string
 * ends up in a log line or an error report, and putting the plaintext there
 * would be the disclosure the sealed path exists to prevent.
 */
export async function prepareSealedDirect(input: OutgoingInput): Promise<OutgoingDecision> {
  const key = input.recipientEncryptionPublicKey;

  // ⚠️ EMPTY STRING IS TREATED AS NO KEY. '' is falsy so this check happens to
  // be right, but the near-misses are not: `!= null`, `typeof === 'string'` and
  // a length-only guard all let '' through to `seal()`, which either throws
  // deep inside WebCrypto or produces an envelope nobody can ever open.
  // "Never published" and "published something empty" must land on the same
  // branch here, because they are the same fact about reachability.
  if (key === null || key === undefined || key === '') {
    return {
      sealed: false,
      reason:
        `${input.recipientId} has not published an encryption key, so this message cannot be ` +
        `sealed to them. They can publish one by creating or re-authenticating their entity; ` +
        `until then only an explicitly unsealed send can reach them.`,
    };
  }

  const sealedBody = await seal(key, input.text);

  const envelope = await signEnvelope(input.senderIdentityPrivateKey, {
    sender: input.senderId,
    recipient: input.recipientId,
    sentAt: input.sentAt ?? new Date().toISOString(),
    sequence: input.sequence,
    sealed: sealedBody,
  });

  return { sealed: true, envelope };
}
