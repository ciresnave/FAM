// Message Commands - Send and Read Messages

import {
  entityRequest,
  getEntitySession,
  loadIdentityPrivateKey,
  loadEncryptionPrivateKey,
} from '../client';
import { readIncoming } from '../../../messaging/receive';
import type { CliConfig } from '../config';
import type { Message } from '../../../types';
import { sendDirect } from '../sendMessage';

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
  
  // ⚠️ A DIRECT MESSAGE SEALS. A CHANNEL MESSAGE STILL DOES NOT, AND SAYS SO.
  //
  // Sealing to a channel needs a group envelope — one content key wrapped per
  // member — and the member keys have to be gathered first. That is built
  // (`src/crypto/groupSealing.ts`) but not wired, and wiring it is its own
  // change. What must NOT happen meanwhile is a channel send that looks
  // identical to a sealed one, because "it sent fine" is how an unsealed path
  // stays unnoticed. So it is named at the moment it happens.
  if (channelId) {
    const response = await entityRequest<SendMessageResponse>(config, '/messages/send', {
      channel_id: channelId,
      text,
    });
    console.log(`Message sent to channel ${channelId} (ID: ${response.message_id})`);
    console.log('NOT SEALED: channel messages are not end-to-end encrypted yet.');
    return;
  }

  const { entityId, sessionId } = await getEntitySession(config);
  const senderIdentityPrivateKey = await loadIdentityPrivateKey(config);

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

  const encryptionPrivateKey = await loadEncryptionPrivateKey(config);

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

    const read = await readIncoming(
      { sealed: msg.sealed, text: msg.text, from_entity: msg.from_entity },
      {
        recipientEncryptionPrivateKey: encryptionPrivateKey,
        // A sender absent from the directory cannot be verified, so nothing is
        // shown for their message. Passing '' rather than skipping the check
        // keeps the failure on the authenticity path instead of inventing a
        // fourth outcome that renders unverified content.
        senderIdentityPublicKey: senderKeys.get(msg.from_entity) ?? '',
      }
    );

    switch (read.kind) {
      case 'plaintext':
        console.log(`  ${read.text}`);
        break;
      case 'opened':
        console.log(`  ${read.text}`);
        console.log('  (sealed — opened here, never readable by the server)');
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
