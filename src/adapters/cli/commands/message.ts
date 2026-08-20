// Message Commands - Send and Read Messages

import { entityRequest } from '../client';
import type { CliConfig } from '../config';

// ============================================================================
// Types
// ============================================================================

interface Message {
  id: number;
  channel_id: string | null;
  from_entity: string;
  to_entity: string | null;
  text: string;
  sent_at: string;
  delivered: boolean;
}

interface SendMessageResponse {
  message_id: number;
}

// ============================================================================
// Send Command
// ============================================================================

export async function runSendCommand(
  target: string,
  text: string,
  config: CliConfig
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
  
  const body: Record<string, string> = { text };
  if (channelId) {
    body.channel_id = channelId;
  } else if (toEntity) {
    body.to_entity = toEntity;
  }
  
  const response = await entityRequest<SendMessageResponse>(config, '/messages/send', body);
  
  const targetDisplay = channelId ? `channel ${channelId}` : toEntity;
  console.log(`Message sent to ${targetDisplay} (ID: ${response.message_id})`);
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
    console.log(`  ${msg.text}`);
    console.log('');
  }
}
