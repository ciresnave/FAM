// Message Send Service
//
// Single authoritative path for sending messages (DM + channel).
// Both the HTTP route (/messages/send) and the WebSocket send handler
// delegate here so that validation, persistence, and push behavior are
// identical — and so future enforcement (permission matrix, availability)
// has exactly one place to live.

import type { DatabaseContext } from '../../db/transaction';
import type { WebSocketManager } from '../websocket';
import type { PushOutcome } from '../websocket';
import type { MessageRefInput } from '../../db/repositories/messageRef';
import type { Message, EntityId, ChannelId } from '../../types';
import { NotFoundError, ForbiddenError, InsufficientCapabilitiesError, EntityNotInChannelError, ValidationError } from '../../types/errors';
import { validateEntityId, validateChannelId, validateMessageText } from '../../types/validation';
import type { PermissionChecker } from './permissionChecker';
import { verifyEnvelope, type SignedEnvelope } from '../../crypto/envelope';

/**
 * Reject anything that is not a well-formed signed envelope.
 *
 * "The server cannot read it" is not "the server accepts anything". An
 * unparseable envelope is undeliverable at every recipient forever, so it is
 * refused at the door rather than persisted as mail nobody can open.
 *
 * Checked before any crypto: `verifyEnvelope` would throw on a missing field
 * rather than returning false, and a 500 for what is plainly a bad request
 * tells the caller the wrong thing about whose fault it is.
 */
function assertEnvelopeShape(envelope: SignedEnvelope): void {
  const sealed = envelope?.sealed;
  const wellFormed =
    envelope != null &&
    typeof envelope.sender === 'string' &&
    typeof envelope.recipient === 'string' &&
    typeof envelope.sentAt === 'string' &&
    typeof envelope.sequence === 'number' &&
    typeof envelope.signature === 'string' &&
    typeof envelope.version === 'number' &&
    sealed != null &&
    typeof sealed.ephemeralPublicKey === 'string' &&
    typeof sealed.iv === 'string' &&
    typeof sealed.ciphertext === 'string' &&
    typeof sealed.version === 'number';

  if (!wellFormed) {
    throw new ValidationError(
      'Malformed sealed envelope: expected version, sender, recipient, sentAt, ' +
        'sequence, signature and a sealed body with version, ephemeralPublicKey, iv and ciphertext.'
    );
  }
}

// ============================================================================
// Message Send Service
// ============================================================================

/**
 * What the sender is told beyond "it was stored".
 *
 * The recipient block is state the RECIPIENT declared or the connection
 * revealed. The sender is already permitted to message this entity and the
 * directory already exposes the same fields for entities it can see, so this
 * discloses nothing new — it exists so the sender can tell a busy peer from a
 * paused one from an absent one.
 */
export interface DeliveryReport {
  outcome: PushOutcome;
  recipient: {
    status: string;
    availability: string;
    queue_empty: boolean | null;
    last_state_change: string | null;
  };
  /**
   * True for `paused`: the recipient DECLARED unavailable. Named to keep the
   * caveat attached to the value — availability is honest-broadcast, not
   * enforced truth, and a caller must not read it as a promise.
   */
  declared_by_recipient: boolean;
}

export interface SendResult {
  message: Message;
  delivery: DeliveryReport;
}

export class MessageSendService {
  constructor(
    private ctx: DatabaseContext,
    private wsManager: WebSocketManager,
    private permissionChecker: PermissionChecker
  ) {}

  /**
   * Send a direct message the SERVER CANNOT READ.
   *
   * ─────────────────────────────────────────────────────────────────────────
   * ⚠️ THE SERVER DOES NOT SEAL. THE SENDER DOES, AND THIS METHOD TAKES THE
   * RESULT. Sealing here would mean holding the plaintext at the moment of
   * encryption — which is what `message-encryption.ts` already does, and is
   * precisely the property sealing exists to remove. A server-sealing version
   * would pass every test one could write about envelopes and signatures while
   * providing none of the guarantee, so the distinction is recorded here rather
   * than left to be re-derived.
   * ─────────────────────────────────────────────────────────────────────────
   *
   * SEPARATE FROM `sendDirectMessage` ON PURPOSE. One method with an optional
   * envelope would be a disjunction — sealed if supplied, plaintext otherwise —
   * and a client bug that dropped the envelope would send plaintext silently
   * while every test still passed. Two methods make the caller name the path,
   * and `messages.sealed` records which one accepted the row.
   *
   * WHAT THE SERVER CHECKS, and what each check is worth:
   *
   *   envelope shape        rejected at the door. "Cannot read it" is not
   *                         "accepts anything" — an unparseable envelope fails
   *                         at every recipient forever.
   *   sender / recipient    must AGREE with the routing. A validly-signed
   *                         envelope naming different parties is not a forgery,
   *                         it is a binding failure between two layers, and
   *                         checking the signature does not catch it.
   *   signature             input validation ONLY. It has NO security value to
   *                         the recipient, who must verify independently —
   *                         that is the entire point of not trusting the relay.
   *                         Do not let this check become the reason a client
   *                         skips its own.
   */
  async sendSealedDirectMessage(
    fromEntityId: EntityId,
    toEntityId: EntityId,
    envelope: SignedEnvelope
  ): Promise<SendResult> {
    validateEntityId(fromEntityId);
    validateEntityId(toEntityId);
    assertEnvelopeShape(envelope);

    const sender = this.requireSender(fromEntityId);

    const recipient = this.ctx.entities.getById(toEntityId);
    if (!recipient) {
      throw new NotFoundError('Entity', toEntityId);
    }

    if (!this.permissionChecker.canDirectMessage(sender, recipient)) {
      throw new ForbiddenError('Not permitted to message this entity');
    }

    // The envelope's own addressing must match how FAM is routing it. The
    // recipient verifies a signature over these fields, so a mismatch means a
    // correctly-verified message that claims to be from or for someone else.
    if (envelope.sender !== fromEntityId) {
      throw new ValidationError(
        `Envelope sender "${envelope.sender}" does not match the sending entity "${fromEntityId}".`
      );
    }
    if (envelope.recipient !== toEntityId) {
      throw new ValidationError(
        `Envelope recipient "${envelope.recipient}" does not match the addressed entity "${toEntityId}".`
      );
    }

    if (!(await verifyEnvelope(sender.public_key, envelope))) {
      throw new ValidationError(
        'Envelope signature does not verify against the sending entity’s public key.'
      );
    }

    // The envelope goes through the SAME at-rest path as any other row. It is
    // already opaque, so this adds no confidentiality — it keeps storage
    // uniform, so the read path needs no branch and the two layers have no way
    // to disagree about how a row was written.
    const serialised = JSON.stringify(envelope);
    const storedText = await this.ctx.messages.prepareStoredText(serialised);

    const message = this.ctx.db.transaction(() => {
      // The race guard. A revocation landing between the check above and this
      // write would otherwise still produce a stored message — the grant said
      // no by the time the row existed. Not redundant with the outer check:
      // that one is the early exit, this one is the invariant.
      if (!this.permissionChecker.canDirectMessage(sender, recipient)) {
        throw new ForbiddenError('Not permitted to message this entity');
      }
      return this.ctx.messages.insertDirectMessage(
        fromEntityId, toEntityId, storedText, serialised, { sealed: true }
      );
    })();

    // `sealed: true` travels with the push so a client cannot mistake an
    // envelope for a message body. Without it the recipient would have to guess
    // from the shape of the text, and a guess that answers wrong displays
    // ciphertext to a user.
    const outcome = this.wsManager.pushToEntity(toEntityId, {
      type: 'message',
      from: fromEntityId,
      channel: null,
      to: toEntityId,
      text: serialised,
      sealed: true,
      timestamp: message.sent_at,
      message_id: message.id,
    } as any);

    const after = this.ctx.entities.getById(toEntityId);

    return {
      message,
      delivery: {
        outcome,
        recipient: {
          status: after?.status ?? 'offline',
          availability: after?.availability ?? 'available',
          queue_empty: after?.queue_empty ?? null,
          last_state_change: after?.last_state_change ?? null,
        },
        declared_by_recipient: outcome === 'paused',
      },
    };
  }

  /**
   * Send a direct message from one entity to another.
   * Enforces the permission policy (default-deny cross-account; deny rules
   * revoke). Persists, then pushes to the recipient if online.
   * Throws FamError subclasses on validation/authorization failure.
   */
  async sendDirectMessage(
    fromEntityId: EntityId,
    toEntityId: EntityId,
    text: string,
    refs?: MessageRefInput[]
  ): Promise<SendResult> {
    validateEntityId(fromEntityId);
    validateEntityId(toEntityId);
    validateMessageText(text);

    const sender = this.requireSender(fromEntityId);

    const recipient = this.ctx.entities.getById(toEntityId);
    if (!recipient) {
      throw new NotFoundError('Entity', toEntityId);
    }

    if (!this.permissionChecker.canDirectMessage(sender, recipient)) {
      throw new ForbiddenError('Not permitted to message this entity');
    }

    const trimmed = text.trim();

    // Encrypt BEFORE the authorizing check, then check and insert with no
    // await between them. Previously the check ran, the persist was awaited,
    // and a revocation landing in that window still produced a stored message
    // — the grant said no by the time the row existed.
    const storedText = await this.ctx.messages.prepareStoredText(trimmed);

    // Validate references BEFORE anything is written.
    //
    // Attaching them after the insert meant an invalid reference threw with the
    // message row already persisted: the caller saw an error and the recipient
    // saw a bare message. "The send failed" and "the send half-succeeded" are
    // different facts, and the second one is the dangerous shape this whole
    // feature exists to remove.
    if (refs) {
      for (const ref of refs) this.ctx.messageRefs.validate(ref);
    }

    const message = this.ctx.db.transaction(() => {
      if (!this.permissionChecker.canDirectMessage(sender, recipient)) {
        throw new ForbiddenError('Not permitted to message this entity');
      }
      const inserted = this.ctx.messages.insertDirectMessage(
        fromEntityId, toEntityId, storedText, trimmed, { sealed: false }
      );
      // Inside the transaction, so a message and its references land together
      // or not at all.
      if (refs) {
        for (const ref of refs) this.ctx.messageRefs.attach(inserted.id, ref);
      }
      return inserted;
    })();

    // Push to recipient if online, and KEEP the answer.
    const outcome = this.wsManager.pushToEntity(toEntityId, {
      type: 'message',
      from: fromEntityId,
      channel: null,
      to: toEntityId,
      text: trimmed,
      timestamp: message.sent_at,
      message_id: message.id,
      refs: refs && refs.length > 0 ? this.ctx.messageRefs.listForMessage(message.id) : undefined,
    } as any);

    // Read the recipient AFTER the push, so the reported state is the state
    // the outcome was decided against rather than a snapshot from before it.
    const after = this.ctx.entities.getById(toEntityId);

    return {
      message,
      delivery: {
        outcome,
        recipient: {
          status: after?.status ?? 'offline',
          availability: after?.availability ?? 'available',
          queue_empty: after?.queue_empty ?? null,
          last_state_change: after?.last_state_change ?? null,
        },
        declared_by_recipient: outcome === 'paused',
      },
    };
  }

  /**
   * Send a message to a channel.
   * Channel membership implies allow (joining opts into messages from
   * members); explicit deny rules on a member's account still filter pushes
   * to that member. Persists once, then pushes to eligible online members
   * except the sender.
   * Throws FamError subclasses on validation/authorization failure.
   */
  async sendChannelMessage(
    fromEntityId: EntityId,
    channelId: ChannelId,
    text: string
  ): Promise<SendResult> {
    validateEntityId(fromEntityId);
    validateChannelId(channelId);
    validateMessageText(text);

    this.requireSender(fromEntityId);

    const channel = this.ctx.channels.getById(channelId);
    if (!channel) {
      throw new NotFoundError('Channel', channelId);
    }

    if (!this.ctx.channels.isMember(channelId, fromEntityId)) {
      throw new EntityNotInChannelError(fromEntityId, channelId);
    }

    const sender = this.ctx.entities.getById(fromEntityId)!;

    const trimmed = text.trim();

    // Same ordering as a DM: the membership that authorizes this send is
    // re-checked with no await between the check and the row.
    const storedText = await this.ctx.messages.prepareStoredText(trimmed);

    const message = this.ctx.db.transaction(() => {
      if (!this.ctx.channels.isMember(channelId, fromEntityId)) {
        throw new EntityNotInChannelError(fromEntityId, channelId);
      }
      return this.ctx.messages.insertChannelMessage(fromEntityId, channelId, storedText, trimmed);
    })();

    // Push to online channel members except the sender, skipping members
    // whose account has denied this sender by rule
    const pushMessage = {
      type: 'message' as const,
      from: fromEntityId,
      channel: channelId,
      to: null,
      text: trimmed,
      timestamp: message.sent_at,
      message_id: message.id,
    };

    const members = this.ctx.channels.getMembers(channelId);
    const outcomes: PushOutcome[] = [];
    for (const member of members) {
      if (member.entity_id === fromEntityId) continue;

      const memberEntity = this.ctx.entities.getById(member.entity_id);
      if (!memberEntity) continue;

      if (this.permissionChecker.isDeniedByRules(sender, memberEntity)) continue;

      const memberOutcome = this.wsManager.pushToEntity(member.entity_id, pushMessage);
      outcomes.push(memberOutcome);
    }

    // A channel send has one outcome per member, so the single-recipient
    // vocabulary does not fit. Reported as the WEAKEST outcome any member got:
    // if anybody is offline or paused, "pushed" would overstate what happened
    // for the channel as a whole. The per-member detail lives in
    // message_deliveries, which is where a caller that needs it should look.
    const weakest: PushOutcome =
      outcomes.includes('offline') ? 'offline'
      : outcomes.includes('paused') ? 'paused'
      : 'pushed';

    return {
      message,
      delivery: {
        outcome: outcomes.length === 0 ? 'offline' : weakest,
        recipient: {
          status: `${outcomes.filter(o => o === 'pushed').length}/${outcomes.length} pushed`,
          availability: 'n/a (channel)',
          queue_empty: null,
          last_state_change: null,
        },
        declared_by_recipient: false,
      },
    };
  }

  // --------------------------------------------------------------------------
  // Internal
  // --------------------------------------------------------------------------

  private requireSender(entityId: EntityId) {
    const sender = this.ctx.entities.getById(entityId);
    if (!sender) {
      throw new NotFoundError('Entity', entityId);
    }
    if (!sender.capabilities.can_send) {
      throw new InsufficientCapabilitiesError('can_send');
    }
    return sender;
  }
}
