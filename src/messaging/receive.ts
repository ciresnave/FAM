// Reading an incoming message — opening it, and deciding whether to believe it.
//
// ─────────────────────────────────────────────────────────────────────────────
// ⚠️ MEASURED BEFORE THIS EXISTED: a sealed message arrives with `sealed: 1`
// and `text` set to the ENVELOPE JSON. A client that does not open it prints
//
//     {"version":1,"sender":"a@…","recipient":"b@…","sealed":{…}}
//
// at a person as though someone had written it. Same failure `assertNotSealed`
// guards for the at-rest mechanism, and it arrives with no error at all.
// ─────────────────────────────────────────────────────────────────────────────
//
// ⚠️ OPENING IS NOT ENOUGH, AND THIS IS THE PART THAT IS EASY TO GET WRONG.
//
// A recipient's encryption key is PUBLIC BY CONSTRUCTION — publishing it is
// what makes them reachable. So ANYONE can seal a message to them. Decryption
// therefore proves exactly one thing: that the message was meant for this
// recipient. It proves NOTHING about who wrote it.
//
// The envelope carries a signature for that, and a signature nobody checks is
// decoration. So this function REQUIRES the sender's public key: there is no
// argument list that lets a caller decrypt without deciding about authenticity.
//
// And a message whose signature does not verify is withheld, not shown with a
// warning. A label is something a person can miss, and the failure it would
// permit is another party's words appearing under a trusted name.

import { open as openSealed } from '../crypto/sealing';
import { openGroup } from '../crypto/groupSealing';
import { verifyEnvelope, verifyGroupEnvelope } from '../crypto/envelope';

export interface IncomingMessage {
  /**
   * Whether the row is sealed.
   *
   * ⚠️ TRANSMITTED BUT UNDECLARED until now: the server SELECTs `*`, so this
   * field reaches clients at runtime while the shared `Message` type omits it.
   * A reader who trusted the type would conclude no such signal existed and
   * render the envelope as text.
   */
  sealed?: boolean | number;
  text: string;
  /** The sender the SERVER says it came from. */
  from_entity: string;
}

export interface ReadKeys {
  /** The recipient's X25519 private half, or null if they have never had one. */
  recipientEncryptionPrivateKey: string | null;
  /** The claimed sender's Ed25519 public key, from the directory. */
  senderIdentityPublicKey: string;
  /**
   * This entity's own id — required to open a CHANNEL message.
   *
   * A group envelope wraps the content key once per member, and the reader
   * selects its own wrapped key by entity id. Being listed is a routing
   * convenience, not an authorisation: the private key is still what opens it.
   */
  recipientEntityId?: string | null;
}

export type IncomingResult =
  | { kind: 'plaintext'; text: string }
  | { kind: 'opened'; text: string }
  | { kind: 'unreadable'; reason: string };

/**
 * Open an incoming message, or say why it cannot be shown.
 *
 * `opened` means BOTH decrypted and signature-verified. Every other outcome is
 * `unreadable` with a reason — there is deliberately no third state that hands
 * back content the caller is expected to treat carefully, because a caller who
 * renders whatever it is given will render that too.
 */
export async function readIncoming(
  message: IncomingMessage,
  keys: ReadKeys
): Promise<IncomingResult> {
  if (!message.sealed) {
    return { kind: 'plaintext', text: message.text };
  }

  if (!keys.recipientEncryptionPrivateKey) {
    // A distinct message on purpose. "You have no encryption key" has a remedy
    // and is a fact about this entity; "this message is damaged" is a fact
    // about the message. Collapsing them sends someone to fix the wrong thing.
    return {
      kind: 'unreadable',
      reason:
        'This message is sealed, and this entity has no encryption key to open it with. ' +
        'Publish one to receive sealed messages; messages sealed before then stay unreadable.',
    };
  }

  const parsed = parseEnvelope(message.text);
  if ('reason' in parsed) return { kind: 'unreadable', reason: parsed.reason };
  const envelope = parsed.envelope;

  // ⚠️ WHICH ENVELOPE IS THIS? A group envelope carries `channel` where a flat
  // one carries `recipient`, and its signature covers a DIFFERENT canonical
  // form. Running a group envelope through the flat path fails verification and
  // reports the SENDER as unverifiable — so a channel message would be sealed,
  // delivered and unreadable, with the recipient told the wrong thing about
  // why. The two are distinguished by shape, not by guessing from the row.
  const isGroup = typeof envelope?.channel === 'string' && envelope.channel !== '';

  // ⚠️ THE ENVELOPE'S OWN CLAIM ABOUT ITS SENDER IS CHECKED AGAINST THE ROW'S.
  // The signature covers `sender`, so a valid signature over a DIFFERENT sender
  // is a correctly signed message from someone else. If the two disagree, one
  // of them is wrong and the recipient must not pick silently.
  const notFromSender = await checkSender(envelope, message, keys, isGroup);
  if (notFromSender) return { kind: 'unreadable', reason: notFromSender };

  if (isGroup && !keys.recipientEntityId) {
    // Without an id there is no way to select a wrapped key, and trying them
    // all would be both wasteful and a way to open a message addressed to
    // somebody else who happens to share this key. Reported rather than
    // guessed at.
    return {
      kind: 'unreadable',
      reason:
        'This is a sealed channel message and no recipient id was supplied, so the right ' +
        'wrapped key cannot be selected.',
    };
  }

  try {
    const text = isGroup
      ? await openGroup(
          keys.recipientEntityId as string,
          keys.recipientEncryptionPrivateKey,
          envelope.sealed
        )
      : await openSealed(keys.recipientEncryptionPrivateKey, envelope.sealed);
    return { kind: 'opened', text };
  } catch (e) {
    // ⚠️ THE REASON MUST NOT CARRY THE ENVELOPE. The underlying error can
    // include ciphertext and key material, and a reason string is exactly what
    // gets printed to a person or into a log.
    return {
      kind: 'unreadable',
      reason: isGroup
        ? 'This channel message could not be opened: either it was not sealed to this entity, ' +
          'or it was sealed to a key that has since been rotated.'
        : 'This message is sealed to a key this entity does not hold, so it cannot be opened. ' +
          'That usually means it was sealed to a key that has since been rotated.',
    };
  }
}

/**
 * The envelope, or the reason it is not one.
 *
 * ⚠️ RETURNS RATHER THAN THROWS. A row marked sealed whose text is not an
 * envelope is a real state — a truncated write, an older format — and an
 * exception here would take down an entire history render because of one bad
 * row. Split out so `readIncoming` reads as one decision per step; the failure
 * it reports is the same one it always did.
 */
function parseEnvelope(text: string): { envelope: any } | { reason: string } {
  try {
    return { envelope: JSON.parse(text) };
  } catch {
    return { reason: 'This message is marked sealed but its envelope could not be parsed.' };
  }
}

/**
 * Is this really from the sender it names? Returns a reason if not, else null.
 *
 * ⚠️ BOTH CHECKS LIVE HERE BECAUSE THEY ANSWER ONE QUESTION, and separating
 * them at the call site invites doing one and not the other. The envelope's own
 * `sender` is compared against the row's, because the signature covers `sender`
 * — a valid signature over a DIFFERENT sender is a correctly signed message
 * from someone else, and when the two disagree the recipient must not pick.
 *
 * ⚠️ NOTHING IS DECRYPTED ON THE FAILURE PATH. Anyone can seal to a published
 * key, so a forged message may well open cleanly; opening it and returning the
 * content behind a flag would put an unknown party's words within reach of any
 * renderer that prints what it is handed.
 */
async function checkSender(
  envelope: any,
  message: IncomingMessage,
  keys: ReadKeys,
  isGroup: boolean
): Promise<string | null> {
  if (envelope?.sender !== message.from_entity) {
    return (
      `This message says it is from ${String(envelope?.sender)} but was delivered as from ` +
      `${message.from_entity}. Those disagree, so it is not shown.`
    );
  }

  // ⚠️ THE VERIFIER MUST MATCH THE ENVELOPE. A group envelope's signature covers
  // a different canonical form — including the RECIPIENT LIST — so checking one
  // with the other's verifier fails and reports the SENDER as unverifiable. The
  // recipient would then be told a third party is suspect when the real answer
  // is that this client read the wrong format.
  // ⚠️ "I HAVE NO KEY FOR THIS SENDER" IS NOT "THIS SIGNATURE IS BAD", AND
  // THESE TWO WERE THE SAME SENTENCE UNTIL IT WAS MEASURED. An empty key fails
  // verification exactly like a wrong one, so an unknown sender was reported as
  // a failed signature — an ACCUSATION against a named third party, produced by
  // a gap in the reader's own directory.
  //
  // Both still withhold the content; that part was already right and must stay.
  // What differs is the remedy, and they point at different people:
  //
  //   unknown  -> a fact about THIS READER. Obtain the key; the sender may be on
  //               another account, or created since the directory was fetched.
  //   unverified -> a claim about the MESSAGE. Someone signed it who is not who
  //               it says.
  if (!keys.senderIdentityPublicKey) {
    return (
      `This message says it is from ${message.from_entity}, and no identity key is known ` +
      `for that sender, so who wrote it cannot be established. It is not shown. This is ` +
      `NOT a failed signature — nothing here suggests the message is forged, only that ` +
      `this client has no key to check it against.`
    );
  }

  let verified = false;
  try {
    verified = isGroup
      ? await verifyGroupEnvelope(keys.senderIdentityPublicKey, envelope)
      : await verifyEnvelope(keys.senderIdentityPublicKey, envelope);
  } catch {
    verified = false;
  }

  if (verified) return null;

  return (
    `This message claims to be from ${message.from_entity} but its signature does not ` +
    'verify against that sender key. It is not shown: anyone can seal a message to a ' +
    'published encryption key, so decrypting it would prove only that it was addressed ' +
    'here, never who wrote it.'
  );
}
