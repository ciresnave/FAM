// Sending a direct message: the policy, with the transport left to the caller.
//
// ─────────────────────────────────────────────────────────────────────────────
// ⚠️ TWO ADAPTERS SEND. ONLY ONE OF THEM MAY DECIDE HOW.
//
// `prepareSealedDirect` already stops the CLI and the MCP adapter answering
// "can this be sealed?" differently. The REST of the policy drifts just as
// easily, and the pieces below are decisions rather than plumbing:
//
//   - a recipient with no key is a REFUSAL, not a quiet downgrade
//   - "not visible" is NOT "has no key"
//   - the refusal happens BEFORE anything is posted
//
// Copying those into a second adapter is how one of them ends up sending
// plaintext where the other refuses — and the difference would show up as a
// message the relay could read, not as a failure.
// ─────────────────────────────────────────────────────────────────────────────
//
// The transport is injected because it is the only part that genuinely differs:
// the CLI posts with `apiRequest` and an explicit session, the MCP adapter goes
// through `FamClient`, which carries its own. Neither difference is a policy
// difference, so neither gets to be one.

import { prepareSealedDirect } from '../crypto/outgoing';
import type { SignedEnvelope } from '../crypto/envelope';

export interface DirectoryEntity {
  id: string;
  /** Null when the entity has never published one. Not coerced. */
  encryption_public_key: string | null;
}

/**
 * What a transport reports back.
 *
 * ⚠️ `response` EXISTS SO THIS SEAM DOES NOT NARROW WHAT THE ADAPTERS ALREADY
 * KNEW. `/messages/send` returns a delivery report, and the MCP tool documents
 * that its result says whether a message was DELIVERED or merely queued.
 * A transport returning only an id would have quietly deleted that — a
 * regression with no failing test, introduced by a refactor that looked like
 * pure tidying.
 */
export interface SendResult {
  messageId: number;
  /** The adapter's own response, passed through untouched. */
  response?: unknown;
}

export interface DirectSendTransport {
  /** The entities this sender can see. Visibility is the transport's business. */
  listVisibleEntities(): Promise<DirectoryEntity[]>;
  sendSealed(recipientId: string, envelope: SignedEnvelope): Promise<SendResult>;
  sendPlaintext(recipientId: string, text: string): Promise<SendResult>;
}

export interface DirectSendInput {
  senderId: string;
  /** Base64 Ed25519 private key, already decrypted. Never leaves the process. */
  senderIdentityPrivateKey: string;
  recipientId: string;
  text: string;
  /**
   * Send unsealed if the recipient cannot receive sealed mail.
   *
   * ⚠️ DEFAULTS TO FALSE, AND THE NAME IS DELIBERATE. "allowPlaintext" states
   * what happens. A `seal` flag defaulting true would read at the call site as
   * though unsetting it were a preference rather than a downgrade, and the
   * person choosing it is entitled to see which one it is.
   */
  allowPlaintext?: boolean;
}

export interface SendOutcome {
  sealed: boolean;
  messageId: number;
  /** The transport's own response, so callers keep what they had. */
  response?: unknown;
  /** Present only on an unsealed send: why it could not be sealed. */
  downgradeReason?: string;
}

export async function sendDirectVia(
  transport: DirectSendTransport,
  input: DirectSendInput
): Promise<SendOutcome> {
  const recipient = await lookupRecipient(transport, input);

  const decision = await prepareSealedDirect({
    senderId: input.senderId,
    senderIdentityPrivateKey: input.senderIdentityPrivateKey,
    recipientId: input.recipientId,
    recipientEncryptionPublicKey: recipient.encryption_public_key,
    text: input.text,
    // ⚠️ NOT A SECURITY CONTROL TODAY, and saying so is the point. The envelope
    // documents `sequence` as where replay protection lives, and nothing on the
    // server enforces monotonicity — a wall-clock value is unique and
    // increasing per sender, which is enough to be a correct input and not
    // enough to be relied on. Whoever implements replay checking should replace
    // this with a persisted counter rather than assume this one already is it.
    sequence: Date.now(),
  });

  if (decision.sealed) {
    const sent = await transport.sendSealed(input.recipientId, decision.envelope);
    return { sealed: true, messageId: sent.messageId, response: sent.response };
  }

  // ⚠️ BEFORE ANYTHING IS POSTED. A refusal raised after the send satisfies a
  // test asserting that it throws, while the plaintext is already gone.
  if (input.allowPlaintext !== true) {
    throw new Error(
      `${decision.reason} Refusing to send unsealed. ` +
        `Re-send with plaintext explicitly allowed if that is what you intend.`
    );
  }

  const sent = await transport.sendPlaintext(input.recipientId, input.text);
  return {
    sealed: false,
    messageId: sent.messageId,
    response: sent.response,
    downgradeReason: decision.reason,
  };
}

/**
 * Find the recipient in the directory this sender can see.
 *
 * ⚠️ "NOT VISIBLE" AND "HAS NO KEY" ARE DIFFERENT FACTS AND MUST NOT COLLAPSE.
 * A recipient the sender cannot see, reported as keyless, turns a lookup or
 * visibility failure into a plaintext send — and that recipient may well have
 * published a key. The downgrade would then be caused by something with nothing
 * to do with their ability to receive sealed mail, which is why this throws
 * rather than returning a null key.
 */
async function lookupRecipient(
  transport: DirectSendTransport,
  input: DirectSendInput
): Promise<DirectoryEntity> {
  const entities = await transport.listVisibleEntities();
  const found = entities.find((e) => e.id === input.recipientId);

  if (!found) {
    throw new Error(
      `${input.recipientId} is not visible to ${input.senderId}, so there is no key to seal to ` +
        `and no way to tell whether they have one. This is not the same as having no ` +
        `encryption key: check the id, and that a grant exists if they are on another account.`
    );
  }

  return found;
}
