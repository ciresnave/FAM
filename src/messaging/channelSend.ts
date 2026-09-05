// Sending to a channel: the policy, with the transport left to the caller.
//
// ─────────────────────────────────────────────────────────────────────────────
// ⚠️ A CHANNEL DOWNGRADE IS EVERY MEMBER'S DOWNGRADE, AND IT IS ALL-OR-NOTHING.
//
// The direct path decides about one recipient. A channel cannot: sealing to the
// members who happen to have keys leaves the rest holding a message they can
// never open, while the sender sees success. The server refuses a partial
// envelope for exactly that reason — the recipient set must equal the
// membership — and the client must not attempt one either. Relying on the far
// side to catch it makes the rule invisible at the place where someone would
// come looking for it.
// ─────────────────────────────────────────────────────────────────────────────
//
// ⚠️ AND THE SENDER IS A RECIPIENT OF THEIR OWN MESSAGE. They are a member, the
// server compares against membership, and a sender omitted from their own
// envelope both fails that check and cannot read their own history. It is the
// one recipient it is natural to forget.

import { sealToMany, type GroupRecipient } from '../crypto/groupSealing';
import { signGroupEnvelope, type SignedGroupEnvelope } from '../crypto/envelope';
import type { DirectoryEntity, SendResult, SendOutcome } from './directSend';

export interface ChannelSendTransport {
  /** Members of the channel, with their keys. Visibility is the transport's business. */
  listChannelMembers(channelId: string): Promise<DirectoryEntity[]>;
  sendSealedChannel(channelId: string, envelope: SignedGroupEnvelope): Promise<SendResult>;
  sendPlaintextChannel(channelId: string, text: string): Promise<SendResult>;
}

export interface ChannelSendInput {
  senderId: string;
  /** Base64 Ed25519 private key, already decrypted. Never leaves the process. */
  senderIdentityPrivateKey: string;
  channelId: string;
  text: string;
  /**
   * Send unsealed if any member cannot receive sealed mail.
   *
   * Defaults to false, matching the direct path. The two must agree: a caller
   * who learned that `fam send` refuses would be surprised to find the channel
   * form quietly downgrading, and the surprise is silent.
   */
  allowPlaintext?: boolean;
}

export async function sendChannelVia(
  transport: ChannelSendTransport,
  input: ChannelSendInput
): Promise<SendOutcome> {
  const members = await transport.listChannelMembers(input.channelId);

  if (members.length === 0) {
    // Distinct from "a member has no key". `sealToMany` also refuses an empty
    // list, but reaching it would mean the membership lookup came back empty —
    // a different problem, and the caller should hear that one rather than a
    // message about encryption keys.
    throw new Error(
      `No members found for channel ${input.channelId}, so there is nobody to seal to. ` +
        `Check the channel id and that this entity is a member of it.`
    );
  }

  // ⚠️ EMPTY STRING COUNTS AS NO KEY, as everywhere else. '' is falsy so a
  // truthiness check is right by accident; `!= null` and a length guard are
  // not, and either would send a key nobody can use into `sealToMany`.
  const keyless = members.filter(
    (m) => m.encryption_public_key === null || m.encryption_public_key === ''
  );

  if (keyless.length > 0) {
    const names = keyless.map((m) => m.id).join(', ');
    const reason =
      `${names} ${keyless.length === 1 ? 'has' : 'have'} published no encryption key, so this ` +
      `channel message cannot be sealed. Sealing to the rest would leave them holding a ` +
      `message they can never open.`;

    // ⚠️ BEFORE ANYTHING IS POSTED, and before any partial envelope is built.
    if (input.allowPlaintext !== true) {
      throw new Error(
        `${reason} Refusing to send unsealed. Re-send with plaintext explicitly allowed if ` +
          `that is what you intend.`
      );
    }

    const sent = await transport.sendPlaintextChannel(input.channelId, input.text);
    return {
      sealed: false,
      messageId: sent.messageId,
      response: sent.response,
      downgradeReason: reason,
    };
  }

  // Every member, INCLUDING the sender. The server compares this set against
  // membership and rejects any difference, in either direction.
  const recipients: GroupRecipient[] = members.map((m) => ({
    entity: m.id,
    publicKey: m.encryption_public_key as string,
  }));

  const sealed = await sealToMany(recipients, input.text);

  const envelope = await signGroupEnvelope(input.senderIdentityPrivateKey, {
    sender: input.senderId,
    channel: input.channelId,
    sentAt: new Date().toISOString(),
    // Same caveat as the direct path: documented as where replay protection
    // lives, and nothing on the server enforces monotonicity yet. Wall-clock is
    // a correct input and not a control; replace it when replay checking exists
    // rather than assuming this already is it.
    sequence: Date.now(),
    sealed,
  });

  const sent = await transport.sendSealedChannel(input.channelId, envelope);
  return { sealed: true, messageId: sent.messageId, response: sent.response };
}
