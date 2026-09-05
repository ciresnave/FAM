// Message Commands - Send and Read Messages

import {
  entityRequest,
  getEntitySession,
  loadIdentityPrivateKey,
  loadEncryptionPrivateKey,
} from '../client';
import { readIncoming } from '../../../messaging/receive';
import { resolveSenderIdentity } from '../../../messaging/senderIdentity';
import { getPeerAnchorKey } from '../peerAnchors';
import type { CliConfig } from '../config';
import type { Message } from '../../../types';
import { sendDirect, sendToChannel } from '../sendMessage';

// ============================================================================
// Types
// ============================================================================

// ⚠️ THE SHARED TYPE, NOT A LOCAL COPY. This file declared its own `Message`
// carrying `delivered: boolean` — a field the shared type OMITS on purpose, so
// the compiler refuses reads of a column nothing has written since schema v7.
// A local duplicate silently restored what the shared type removed, and it is
// how `sealed` came to be missing here while the server was sending it.

interface SendMessageResponse {
  message_id: number;
}

// ============================================================================
// Send Command
// ============================================================================

export async function runSendCommand(
  target: string,
  text: string,
  config: CliConfig,
  flags?: Record<string, string | boolean>
): Promise<void> {
  if (!text) {
    throw new Error('Usage: fam send <target> <message>');
  }
  
  // Parse target: either "channel:name" or entity ID
  let channelId: string | undefined;
  let toEntity: string | undefined;
  
  if (target.startsWith('channel:')) {
    const channelName = target.slice(8);
    // Look up channel by name
    const channelsResponse = await entityRequest<{ channels: Array<{ id: string; name: string }> }>(
      config,
      '/channels/list',
      { include_public: true }
    );
    
    const channel = channelsResponse.channels.find(c => c.name === channelName);
    if (!channel) {
      throw new Error(`Channel not found: ${channelName}`);
    }
    channelId = channel.id;
  } else {
    toEntity = target;
  }
  
  // ⚠️ BOTH FORMS SEAL NOW, AND A CHANNEL IS ALL-OR-NOTHING. One content key
  // encrypts the body once and is wrapped per member; the server requires the
  // recipient set to equal the membership, because sealing to the members who
  // happen to have keys leaves the rest holding a message they can never open
  // while the sender sees success.
  const { entityId, sessionId } = await getEntitySession(config);
  const senderIdentityPrivateKey = await loadIdentityPrivateKey(config);

  if (channelId) {
    const outcome = await sendToChannel(config, {
      senderId: entityId,
      senderIdentityPrivateKey,
      sessionId,
      channelId,
      text,
      allowPlaintext: flags?.plaintext === true,
    });

    console.log(`Message sent to channel ${channelId} (ID: ${outcome.messageId})`);
    if (outcome.sealed) {
      console.log('Sealed to every member: the server cannot read this message.');
    } else {
      console.log(`NOT SEALED: ${outcome.downgradeReason}`);
    }
    return;
  }

  const outcome = await sendDirect(config, {
    senderId: entityId,
    senderIdentityPrivateKey,
    sessionId,
    recipientId: toEntity!,
    text,
    // Explicit, not inferred. `--plaintext` is the only way to take the
    // unsealed path, and taking it requires having typed the word.
    allowPlaintext: flags?.plaintext === true,
  });

  console.log(`Message sent to ${toEntity} (ID: ${outcome.messageId})`);

  if (outcome.sealed) {
    console.log('Sealed: the server cannot read this message.');
  } else {
    // The downgrade is reported every time it happens. A one-line difference
    // that a person can miss is still better than none, and this one names the
    // recipient and the reason rather than saying "unencrypted".
    console.log(`NOT SEALED: ${outcome.downgradeReason}`);
  }
}

// ============================================================================
// History Command
// ============================================================================

export async function runHistoryCommand(
  flags: Record<string, string | boolean>,
  config: CliConfig
): Promise<void> {
  const channelId = flags.channel as string | undefined;
  const entityId = flags.entity as string | undefined;
  const limit = parseInt((flags.limit as string) || '50', 10);
  
  if (!channelId && !entityId) {
    throw new Error('Usage: fam history --channel <id> or --entity <id>');
  }
  
  const body: Record<string, unknown> = { limit };
  if (channelId) {
    body.channel_id = channelId;
  } else if (entityId) {
    body.other_entity_id = entityId;
  }
  
  const response = await entityRequest<{ messages: Message[] }>(config, '/messages/history', body);
  
  const messages = response.messages;
  
  if (messages.length === 0) {
    console.log('No messages found.');
    return;
  }
  
  // ⚠️ OPENING NEEDS TWO KEYS, AND THE SECOND ONE IS THE POINT. The recipient's
  // private half decrypts; the SENDER's public half is what says who wrote it.
  // A recipient's encryption key is public by construction, so anyone can seal
  // to them — decryption alone proves only that a message was addressed here.
  // The directory is fetched once and indexed, rather than per message.
  const directory = await entityRequest<{ entities: Array<{ id: string; public_key: string }> }>(
    config,
    '/entities/list',
    {}
  );
  const senderKeys = new Map(directory.entities.map((e) => [e.id, e.public_key]));

  // ⚠️ THE DIRECTORY IS THE RELAY'S WORD. Every signature check in FAM used to
  // terminate at a value the server controls: `entities.public_key` is a column
  // in the server's own database, served over `/entities/list`. A malicious home
  // server needs nobody's private key — it publishes its own for an entity and
  // forges freely, and an INVALID key would be noticed while a VALID substituted
  // one is undetectable.
  //
  // So the directory key is now an INPUT to a decision rather than the answer.
  // `resolveSenderIdentity` prefers a key the sender's account vouched for, and
  // REFUSES outright when the two disagree — that disagreement is the attack
  // this tier exists to detect, and silently preferring the vouched one would
  // discard the only evidence it happened.
  const identities = new Map<string, Awaited<ReturnType<typeof resolveSenderIdentity>>>();
  for (const senderId of new Set(messages.map((m) => m.from_entity))) {
    identities.set(senderId, await identityFor(config, senderId, senderKeys.get(senderId) ?? null));
  }

  const encryptionPrivateKey = await loadEncryptionPrivateKey(config);
  const { entityId: readerEntityId } = await getEntitySession(config);

  console.log(`\nMessages (${messages.length}):\n`);

  for (const msg of messages) {
    const time = new Date(msg.sent_at).toLocaleString();
    const from = msg.from_entity;
    const to = msg.to_entity || msg.channel_id;

    // No delivery marker here. Delivery is per (message, recipient) since
    // schema v7, so a single flag on the message cannot answer it — a channel
    // message is delivered to some members and not others at the same time.
    // `messages.delivered` still exists but is vestigial: nothing writes it,
    // so rendering it would have marked every message "[undelivered]" forever.
    console.log(`[${time}] ${from} → ${to}`);

    const identity = identities.get(msg.from_entity)!;

    if (identity.kind === 'refused') {
      // ⚠️ NOTHING IS OPENED. The identity could not be established, or it was
      // established and CONTRADICTS what the server served. Either way the
      // message body is never decrypted into anything a renderer could print.
      console.log(`  [not shown] ${identity.reason}`);
      console.log('');
      continue;
    }

    const read = await readIncoming(
      { sealed: msg.sealed, text: msg.text, from_entity: msg.from_entity },
      {
        recipientEncryptionPrivateKey: encryptionPrivateKey,
        senderIdentityPublicKey: identity.publicKey,
        // Required for a CHANNEL message: the group envelope wraps the content
        // key once per member and the reader selects its own by entity id.
        recipientEntityId: readerEntityId,
      }
    );

    switch (read.kind) {
      case 'plaintext':
        console.log(`  ${read.text}`);
        break;
      case 'opened':
        console.log(`  ${read.text}`);
        console.log(
          identity.kind === 'vouched'
            ? '  (sealed, and the sender key was vouched for by their account — not the relay)'
            : '  (sealed — opened here, never readable by the server. Sender identity is ' +
              'UNVOUCHED: still the relay’s word. `fam account trust` to change that.)'
        );
        break;
      case 'unreadable':
        // ⚠️ THE ENVELOPE IS NEVER PRINTED AS A FALLBACK. Before this, `text`
        // for a sealed message WAS the envelope JSON, so "show what we have"
        // put a JSON blob in front of a person as though someone had written
        // it — with no error anywhere.
        console.log(`  [not shown] ${read.reason}`);
        break;
    }

    console.log('');
  }
}

/**
 * Gather what `resolveSenderIdentity` needs for one sender.
 *
 * The DECISION is not here — it lives in `senderIdentity.ts` so the CLI and the
 * MCP adapter cannot answer "whose key do I trust" differently. This is the
 * transport half: the locally pinned anchor, and the voucher records the server
 * holds. The records are fetched from the relay ON PURPOSE — they are signed by
 * the account key, so a relay can withhold them but cannot forge one, and
 * withholding produces `unvouched` rather than a wrong answer.
 */
async function identityFor(
  config: CliConfig,
  senderId: string,
  serverSuppliedKey: string | null
) {
  const at = senderId.indexOf('@');
  const accountId = at === -1 ? senderId : senderId.slice(at + 1);

  const accountPublicKey = await getPeerAnchorKey(accountId);

  let records: any[] = [];
  if (accountPublicKey) {
    // Only worth asking once an anchor is held: without one, no record can be
    // verified and the answer is `unvouched` regardless.
    try {
      const listed = await entityRequest<{ records: any[] }>(config, '/vouchers/list', {
        subject_entity_id: senderId,
      });
      records = listed.records ?? [];
    } catch {
      // A relay that cannot or will not answer produces `unvouched`, never a
      // pass: the absence of records is not evidence of anything.
      records = [];
    }
  }

  return resolveSenderIdentity({ entityId: senderId, serverSuppliedKey, accountPublicKey, records });
}
