#!/usr/bin/env bun
/**
 * FAM MCP Server for Claude Code
 *
 * Spawned by Claude Code as a stdio MCP server (one per instance).
 * Connects to the FAM HTTP/WebSocket server and exposes FAM operations as MCP tools.
 * Uses notifications/claude/channel for real-time message push.
 *
 * Usage:
 *   claude --dangerously-load-development-channels fam
 *
 * With .mcp.json:
 *   { "fam": { "command": "bun", "args": ["src/adapters/mcp/server.ts"] } }
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { FamClient } from './client';
import { ChannelPushHandler } from './channel-push';
import { FAM_TOOLS } from './tools';
import { decryptPrivateKey } from '../../crypto/encrypt';
import { sign, base64ToBuffer } from '../../crypto/keys';
import type { EncryptedKeyFile } from '../../types';
import { getActiveEntityCredentials } from '../cli/config';
import { homedir } from 'os';
import { join } from 'path';
import { DEFAULT_SERVER_URL, DEFAULT_WS_URL } from '../../config';

// ============================================================================
// Configuration
// ============================================================================

const FAM_SERVER_URL = process.env.FAM_SERVER_URL || DEFAULT_SERVER_URL;
const FAM_WS_URL = process.env.FAM_WS_URL || DEFAULT_WS_URL;
const FAM_ENTITIES_DIR = join(homedir(), '.fam');

// ============================================================================
// Utility
// ============================================================================

function log(msg: string) {
  // MCP stdio servers must only use stderr for logging
  console.error(`[fam-mcp] ${msg}`);
}

// ============================================================================
// Credential Loading
// ============================================================================

interface EntityCredentials {
  entity_id: string;
  encrypted_key_file: string;
  display_name?: string;
}

/**
 * Load the active entity's credentials using the shared loader (versioned,
 * migration-aware). Checks FAM_CREDENTIALS path first, then the default
 * location — same resolution rules as the CLI.
 */
async function loadCredentials(): Promise<EntityCredentials> {
  const credentialsPath = process.env.FAM_CREDENTIALS
    ?? join(FAM_ENTITIES_DIR, 'credentials.json');

  try {
    return await getActiveEntityCredentials(credentialsPath);
  } catch (e) {
    if (e instanceof Error && e.name === 'UnsupportedFormatVersionError') throw e;
    throw new Error(
      `No FAM credentials found at ${credentialsPath}. Run the FAM account setup first:\n` +
      `  1. Start the FAM server: bun src/server/http.ts\n` +
      `  2. Visit ${FAM_SERVER_URL}/accounts/authorize/google (or github)\n` +
      `  3. Create an entity via the API\n` +
      `  4. Save credentials to ${credentialsPath}`
    );
  }
}

async function decryptEntityKey(
  encryptedKeyFile: EncryptedKeyFile,
  passkey: string
): Promise<string> {
  try {
    return await decryptPrivateKey(encryptedKeyFile, passkey);
  } catch (e) {
    throw new Error(
      `Failed to decrypt private key. Wrong passkey?\n` +
      `Entity: ${encryptedKeyFile.entity_id}\n` +
      `Error: ${e instanceof Error ? e.message : String(e)}`
    );
  }
}

// ============================================================================
// MCP Server
// ============================================================================

/**
 * Say what actually happened, in words an agent will act on correctly.
 *
 * "Message sent" was the whole problem: it read identically for a live
 * recipient, one that had declared itself unavailable, and one offline for a
 * week. An agent seeing three identical successes concludes silence is a
 * choice, and waits on someone who never received the message.
 */
function describeDelivery(
  target: string,
  result: {
    message_id: number;
    delivery?: { outcome: string; recipient?: { queue_empty: boolean | null } };
  }
): string {
  const id = `ID: ${result.message_id}`;
  const d = result.delivery;
  if (!d) {
    return `Message stored for ${target} (${id}). This server does not report delivery state.`;
  }

  const queue = d.recipient?.queue_empty === false ? ' They have declared work pending.' : '';

  switch (d.outcome) {
    case 'pushed':
      return `DELIVERED to ${target} (${id}). It reached them; silence from here is theirs.${queue}`;
    case 'paused':
      return (
        `QUEUED for ${target} (${id}). They have declared themselves unavailable, so this was ` +
        `held deliberately and they will see it when they resume. DO NOT read silence as a ` +
        `reply — they have not received it yet.${queue}`
      );
    case 'offline':
      return (
        `QUEUED for ${target} (${id}). They are not connected; they will see it on reconnect. ` +
        `DO NOT read silence as a reply — they have not received it yet.${queue}`
      );
    default:
      return `Message stored for ${target} (${id}), delivery state "${d.outcome}".`;
  }
}

async function main() {
  // 1. Load credentials
  const credentials = await loadCredentials();
  log(`Loaded credentials for: ${credentials.entity_id}`);
  
  // 2. Get passkey from env or prompt
  const passkey = process.env.FAM_PASSKEY;
  if (!passkey) {
    throw new Error(
      'FAM_PASSKEY environment variable required for key decryption.\n' +
      'Set it to your account passkey.'
    );
  }
  
  // 3. Connect to FAM server
  const client = new FamClient({
    serverUrl: FAM_SERVER_URL,
    wsUrl: FAM_WS_URL,
  });

  // Surface a permanent disconnection instead of going quiet. Reconnection
  // stopping used to be a single console line deep in the client, so from here
  // a dead channel and an idle one looked identical.
  client.onTerminalFailure((reason) => {
    log('');
    log(`  FAM connection has STOPPED and will not retry: ${reason}`);
    log(`  Messages sent to ${credentials.entity_id} will not arrive.`);
    log(`  Restart this MCP server after fixing the entity to reconnect.`);
    log('');
  });

  // 4. Authenticate with FAM server
  // First, we need to get the entity's public key from the credentials
  // The encrypted key file contains the public key
  const keyFileData: EncryptedKeyFile = JSON.parse(credentials.encrypted_key_file);
  const publicKey = keyFileData.public_key;
  
  // Connect and get nonce
  const { nonce } = await client.connect(credentials.entity_id, publicKey);
  log(`Got nonce challenge: ${nonce.slice(0, 8)}...`);
  
  // Decrypt private key
  const privateKeyBase64 = await decryptEntityKey(keyFileData, passkey);
  
  // Sign the nonce (must be base64-decoded first, not UTF-8 encoded)
  const nonceBytes = base64ToBuffer(nonce);
  const signature = await sign(nonceBytes, privateKeyBase64);
  
  // Authenticate
  const authResponse = await client.authenticate(
    credentials.entity_id,
    nonce,
    signature
  );
  log(`Authenticated. Session: ${authResponse.session_id}`);
  log(`Undelivered messages: ${authResponse.undelivered_messages?.length ?? 0}`);
  
  // Set credentials for re-authentication on reconnect
  client.setAuthCredentials(publicKey, async (data: Uint8Array) => {
    return await sign(data, privateKeyBase64);
  });
  
  // Create MCP server first so the push handler can process the backlog
  const mcp = new Server(
    { name: 'fam', version: '0.1.0' },
    {
      capabilities: {
        experimental: { 'claude/channel': {} },
        tools: {},
      },
      instructions: `You are connected to the FAM (Federated Agent Messaging) network. Other agents and humans can see you and send you messages.

IMPORTANT: When you receive a <channel source="fam" ...> message, RESPOND IMMEDIATELY. Do not wait until your current task is finished. Pause what you are doing, reply to the message, then resume your work. Treat incoming messages like a coworker tapping you on the shoulder — answer right away, even if you're in the middle of something.

Read the from_entity, from_display_name, and channel attributes to understand who sent the message and where.

Available tools:
- fam_list_entities: Discover other entities on the network
- fam_send_message: Send a message to another entity (DM or channel)
- fam_create_channel: Create a new communication channel
- fam_join_channel: Join an existing channel
- fam_list_channels: List channels you can see
- fam_list_channel_members: See who's in a channel
- fam_get_history: Get message history
- fam_set_status: Update your status (online, away, busy)
- fam_send_message: The result says whether the message was DELIVERED or merely
  QUEUED. Read it. A queued message has not been seen, so silence from that peer
  is not an answer and waiting on one is a mistake.
- fam_set_availability: Pause/resume incoming messages (available/unavailable)
- fam_set_queue_state: Declare whether you have work pending. Nothing else can
  tell — being alive is not the same as being busy. Declare false when you take
  work on and true when you finish; declaring only one edge is worse than not
  declaring at all.

When you start, proactively list entities and channels to understand who's available.`,
    }
  );
  
  // 6. Register tool handlers
  mcp.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: FAM_TOOLS,
  }));
  
  mcp.setRequestHandler(CallToolRequestSchema, async (req) => {
    const { name, arguments: args } = req.params;
    
    try {
      switch (name) {
        case 'fam_list_entities': {
          const response = await client.listEntities(args as any);
          if (response.length === 0) {
            return {
              content: [{ type: 'text' as const, text: 'No entities found on the network.' }],
            };
          }
          const lines = response.map((e) => {
            const parts = [
              `ID: ${e.id}`,
              `Type: ${e.type}`,
              `Status: ${e.last_seen ? 'online' : 'offline'}`,
            ];
            if (e.display_name) parts.push(`Name: ${e.display_name}`);
            parts.push(`Capabilities: ${Object.entries(e.capabilities).filter(([_, v]) => v).map(([k]) => k).join(', ')}`);
            return parts.join('\n  ');
          });
          return {
            content: [{ type: 'text' as const, text: `Found ${response.length} entity(ies):\n\n${lines.join('\n\n')}` }],
          };
        }
        
        case 'fam_send_message': {
          const { to_entity, channel_id, text } = args as any;
          if (!text) {
            return {
              content: [{ type: 'text' as const, text: 'Message text is required' }],
              isError: true,
            };
          }
          if (to_entity) {
            const result = await client.sendDirectMessage(to_entity, text);
            return {
              content: [{ type: 'text' as const, text: describeDelivery(to_entity, result) }],
            };
          } else if (channel_id) {
            const result = await client.sendChannelMessage(channel_id, text);
            return {
              content: [{ type: 'text' as const, text: describeDelivery(`channel ${channel_id}`, result) }],
            };
          } else {
            return {
              content: [{ type: 'text' as const, text: 'Must specify either to_entity or channel_id' }],
              isError: true,
            };
          }
        }
        
        case 'fam_create_channel': {
          const { name: channelName, is_public } = args as any;
          if (!channelName) {
            return {
              content: [{ type: 'text' as const, text: 'Channel name is required' }],
              isError: true,
            };
          }
          const channel = await client.createChannel(channelName, is_public);
          return {
            content: [{ type: 'text' as const, text: `Channel created: ${channel.name} (ID: ${channel.id})` }],
          };
        }
        
        case 'fam_join_channel': {
          const { channel_id } = args as any;
          if (!channel_id) {
            return {
              content: [{ type: 'text' as const, text: 'Channel ID is required' }],
              isError: true,
            };
          }
          await client.joinChannel(channel_id);
          return {
            content: [{ type: 'text' as const, text: `Joined channel ${channel_id}` }],
          };
        }
        
        case 'fam_list_channels': {
          const { include_public } = args as any;
          const channels = await client.listChannels(include_public);
          if (channels.length === 0) {
            return {
              content: [{ type: 'text' as const, text: 'No channels found.' }],
            };
          }
          const lines = channels.map((c) => {
            return [
              `Name: ${c.name}`,
              `ID: ${c.id}`,
              `Public: ${c.is_public ? 'yes' : 'no'}`,
              `Created by: ${c.created_by_entity}`,
            ].join('\n  ');
          });
          return {
            content: [{ type: 'text' as const, text: `Found ${channels.length} channel(s):\n\n${lines.join('\n\n')}` }],
          };
        }
        
        case 'fam_list_channel_members': {
          const { channel_id } = args as any;
          if (!channel_id) {
            return {
              content: [{ type: 'text' as const, text: 'Channel ID is required' }],
              isError: true,
            };
          }
          const members = await client.listChannelMembers(channel_id);
          if (members.length === 0) {
            return {
              content: [{ type: 'text' as const, text: 'No members in this channel.' }],
            };
          }
          const lines = members.map((m) => `${m.entity_id} (${m.role})`);
          return {
            content: [{ type: 'text' as const, text: `Members (${members.length}):\n${lines.join('\n')}` }],
          };
        }
        
        case 'fam_get_history': {
          const { channel_id, other_entity_id, limit } = args as any;
          if (!channel_id && !other_entity_id) {
            return {
              content: [{ type: 'text' as const, text: 'Must specify either channel_id or other_entity_id' }],
              isError: true,
            };
          }
          const options = channel_id
            ? { channelId: channel_id }
            : { otherEntityId: other_entity_id };
          const messages = await client.getHistory(options, limit);
          if (messages.length === 0) {
            return {
              content: [{ type: 'text' as const, text: 'No messages found.' }],
            };
          }
          const lines = messages.map((m) => {
            const from = m.from_entity;
            const to = m.to_entity || m.channel_id;
            const time = new Date(m.sent_at).toLocaleString();
            return `[${time}] ${from} → ${to}:\n${m.text}`;
          });
          return {
            content: [{ type: 'text' as const, text: `${messages.length} message(s):\n\n${lines.join('\n\n')}` }],
          };
        }
        
        case 'fam_set_status': {
          const { status } = args as any;
          if (!status) {
            return {
              content: [{ type: 'text' as const, text: 'Status is required' }],
              isError: true,
            };
          }
          await client.setStatus(status);
          return {
            content: [{ type: 'text' as const, text: `Status updated to: ${status}` }],
          };
        }
        
        case 'fam_set_availability': {
          const { availability } = args as any;
          if (!availability || !['available', 'unavailable'].includes(availability)) {
            return {
              content: [{ type: 'text' as const, text: 'availability must be "available" or "unavailable"' }],
              isError: true,
            };
          }
          const result = await client.setAvailability(availability);
          const suffix = availability === 'available' && result.messages_pushed > 0
            ? ` (${result.messages_pushed} queued message(s) pushed)`
            : '';
          return {
            content: [{ type: 'text' as const, text: `Availability set to: ${availability}${suffix}` }],
          };
        }
        
        case 'fam_set_queue_state': {
          const { queue_empty } = args as any;
          // Explicit boolean only. Truthy coercion would let the string
          // "false" declare the opposite of what it means, on a value a
          // supervisor reads to decide whether to dispatch work.
          if (typeof queue_empty !== 'boolean') {
            return {
              content: [{ type: 'text' as const, text: 'queue_empty must be true or false' }],
              isError: true,
            };
          }
          await client.setQueueEmpty(queue_empty);
          return {
            content: [{
              type: 'text' as const,
              text: queue_empty
                ? 'Declared: queue empty. Remember to declare false when you pick work up.'
                : 'Declared: working. Remember to declare true when you finish.',
            }],
          };
        }

        case 'fam_kick_member': {
          const { channel_id, target_entity } = args as any;
          if (!channel_id || !target_entity) {
            return {
              content: [{ type: 'text' as const, text: 'channel_id and target_entity are required' }],
              isError: true,
            };
          }
          await client.request('/channels/kick', {
            entity_id: client.getEntityId(),
            channel_id,
            target_entity,
          });
          return {
            content: [{ type: 'text' as const, text: `Kicked ${target_entity} from channel ${channel_id}` }],
          };
        }
        
        case 'fam_set_member_role': {
          const { channel_id, target_entity, role } = args as any;
          if (!channel_id || !target_entity || !role) {
            return {
              content: [{ type: 'text' as const, text: 'channel_id, target_entity, and role are required' }],
              isError: true,
            };
          }
          await client.request('/channels/set-role', {
            entity_id: client.getEntityId(),
            channel_id,
            target_entity,
            role,
          });
          return {
            content: [{ type: 'text' as const, text: `Set ${target_entity}'s role to "${role}" in channel ${channel_id}` }],
          };
        }
        
        case 'fam_invite_to_channel': {
          const { channel_id, invited_entity } = args as any;
          if (!channel_id || !invited_entity) {
            return {
              content: [{ type: 'text' as const, text: 'channel_id and invited_entity are required' }],
              isError: true,
            };
          }
          await client.request('/channels/invite', {
            entity_id: client.getEntityId(),
            channel_id,
            invited_entity,
          });
          return {
            content: [{ type: 'text' as const, text: `Invited ${invited_entity} to channel ${channel_id}` }],
          };
        }
        
        case 'fam_list_invitations': {
          const response = await client.request<{ invitations: Array<{ id: string; channel_id: string; invited_by: string; status: string }> }>('/channels/invitations', {
            entity_id: client.getEntityId(),
          });
          if (response.invitations.length === 0) {
            return {
              content: [{ type: 'text' as const, text: 'No pending invitations.' }],
            };
          }
          const lines = response.invitations.map((i) => `Channel: ${i.channel_id} (invited by ${i.invited_by})`);
          return {
            content: [{ type: 'text' as const, text: `Invitations (${response.invitations.length}):\n${lines.join('\n')}` }],
          };
        }
        
        default:
          throw new Error(`Unknown tool: ${name}`);
      }
    } catch (e) {
      return {
        content: [
          {
            type: 'text' as const,
            text: `Error: ${e instanceof Error ? e.message : String(e)}`,
          },
        ],
        isError: true,
      };
    }
  });
  
  // 7. Connect MCP over stdio
  await mcp.connect(new StdioServerTransport());
  log('MCP connected');
  
  // 8. Start channel push handler
  const pushHandler = new ChannelPushHandler(mcp, client, credentials.display_name || credentials.entity_id);
  pushHandler.start();
  log('Channel push handler started');
  
  // 9. Dispatch undelivered message backlog from initial auth
  // (pushHandler registers the undelivered handler, which pushes to MCP and acks)
  client.dispatchUndelivered(authResponse.undelivered_messages ?? []);
  
  // 10. Connect WebSocket for real-time push
  client.connectWebSocket();
  log('WebSocket connected');
  
  // 11. Start heartbeat
  const heartbeatTimer = setInterval(async () => {
    try {
      await client.heartbeat();
    } catch {
      // Non-critical
    }
  }, 30_000);
  
  // 12. Clean up on exit
  const cleanup = async () => {
    clearInterval(heartbeatTimer);
    pushHandler.stop();
    await client.disconnect();
    log('Disconnected from FAM server');
    process.exit(0);
  };
  
  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);
  
  log(`FAM MCP server ready (entity: ${credentials.entity_id})`);
}

main().catch((e) => {
  log(`Fatal: ${e instanceof Error ? e.message : String(e)}`);
  process.exit(1);
});
