// Sending a direct message from a client — sealed unless told otherwise.
//
// ─────────────────────────────────────────────────────────────────────────────
// ⚠️ PUBLISHING MADE ENTITIES REACHABLE. THIS IS WHAT ACTUALLY SENDS SEALED.
//
// `canReceiveSealed` became true for entities that publish, and the CLI still
// called `/messages/send` unconditionally — so "a message travelled sealed" was
// still false. That is the same gap as before, one layer up, and it would have
// gone on reading as finished.
// ─────────────────────────────────────────────────────────────────────────────
//
// The decision itself is NOT here. `prepareSealedDirect` decides whether an
// envelope can be built, so the CLI and the MCP adapter cannot answer that
// question differently. What lives here is the part that is genuinely the
// client's: looking the recipient up, and what to do about a refusal.

import { apiRequest } from './client';
import type { CliConfig } from './config';
import { prepareSealedDirect } from '../../crypto/outgoing';

export interface DirectSendInput {
  senderId: string;
  /** Base64 Ed25519 private key, already decrypted. Never leaves the process. */
  senderIdentityPrivateKey: string;
  sessionId: string;
  recipientId: string;
  text: string;
  /**
   * Send unsealed if the recipient cannot receive sealed mail.
   *
   * ⚠️ DEFAULTS TO FALSE, AND THE NAME IS DELIBERATE. "allowPlaintext" states
   * what actually happens. A flag called `seal` defaulting true would read at
   * the call site as though unsetting it were a preference rather than a
   * downgrade, and the person choosing it is entitled to see which one it is.
   */
  allowPlaintext?: boolean;
}

export interface SendOutcome {
  sealed: boolean;
  messageId: number;
  /** Present only on an unsealed send: why it could not be sealed. */
  downgradeReason?: string;
}

interface DirectoryEntity {
  id: string;
  encryption_public_key: string | null;
}

/**
 * Send a direct message, sealing it unless the caller explicitly allowed
 * otherwise and the recipient genuinely cannot receive sealed mail.
 */
export async function sendDirect(
  config: CliConfig,
  input: DirectSendInput
): Promise<SendOutcome> {
  const recipient = await lookupRecipient(config, input);

  const decision = await prepareSealedDirect({
    senderId: input.senderId,
    senderIdentityPrivateKey: input.senderIdentityPrivateKey,
    recipientId: input.recipientId,
    recipientEncryptionPublicKey: recipient.encryption_public_key,
    text: input.text,
    // ⚠️ NOT A SECURITY CONTROL TODAY, and saying so is the point. The envelope
    // documents `sequence` as where replay protection lives, and nothing on the
    // server enforces monotonicity yet — a wall-clock value is unique and
    // increasing per sender, which is enough to be a correct input and not
    // enough to be relied on. Whoever implements replay checking should replace
    // this with a persisted counter rather than assume this one is already it.
    sequence: Date.now(),
  });

  if (decision.sealed) {
    const res = await apiRequest<{ message_id: number }>(config, '/messages/send-sealed', {
      entity_id: input.senderId,
      session_id: input.sessionId,
      to_entity: input.recipientId,
      envelope: decision.envelope,
    });

    return { sealed: true, messageId: res.message_id };
  }

  // ⚠️ THE REFUSAL HAPPENS BEFORE ANYTHING IS POSTED. Throwing after the send
  // would satisfy a test asserting that it throws while the plaintext was
  // already on the server.
  if (input.allowPlaintext !== true) {
    throw new Error(
      `${decision.reason} Refusing to send unsealed. ` +
        `Re-send with plaintext explicitly allowed if that is what you intend.`
    );
  }

  const res = await apiRequest<{ message_id: number }>(config, '/messages/send', {
    entity_id: input.senderId,
    session_id: input.sessionId,
    to_entity: input.recipientId,
    text: input.text,
  });

  return { sealed: false, messageId: res.message_id, downgradeReason: decision.reason };
}

/**
 * Find the recipient in the directory the sender can see.
 *
 * ⚠️ "NOT VISIBLE" AND "HAS NO KEY" ARE DIFFERENT FACTS AND MUST NOT COLLAPSE.
 * If a recipient the sender cannot see were reported as keyless, a lookup or
 * visibility failure would turn into a plaintext send — and the recipient may
 * well have published a key. That downgrade would be caused by something with
 * nothing to do with the recipient's ability to receive sealed mail, which is
 * why it throws here rather than returning a null key.
 */
async function lookupRecipient(
  config: CliConfig,
  input: DirectSendInput
): Promise<DirectoryEntity> {
  const res = await apiRequest<{ entities: DirectoryEntity[] }>(config, '/entities/list', {
    entity_id: input.senderId,
    session_id: input.sessionId,
  });

  const found = res.entities.find((e) => e.id === input.recipientId);

  if (!found) {
    throw new Error(
      `${input.recipientId} is not visible to ${input.senderId}, so there is no key to seal to ` +
        `and no way to tell whether they have one. This is not the same as having no ` +
        `encryption key: check the id, and that a grant exists if they are on another account.`
    );
  }

  return found;
}
