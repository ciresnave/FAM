// Channel Commands - Create, Join, List, Manage Channels

import { entityRequest } from '../client';
import type { CliConfig } from '../config';

// ============================================================================
// Types
// ============================================================================

interface Channel {
  id: string;
  name: string;
  created_by_entity: string;
  is_public: boolean;
  created_at: string;
}

interface ChannelMember {
  channel_id: string;
  entity_id: string;
  role: string;
  joined_at: string;
}

interface Invitation {
  id: string;
  channel_id: string;
  invited_by: string;
  invited_entity: string;
  status: string;
  created_at: string;
}

// ============================================================================
// Channel Command Router
// ============================================================================

export async function runChannelCommand(
  subcommand: string | null,
  positional: string[],
  flags: Record<string, string | boolean>,
  config: CliConfig
): Promise<void> {
  switch (subcommand) {
    case 'list':
      await listChannels(flags, config);
      break;
      
    case 'create':
      await createChannel(positional, flags, config);
      break;
      
    case 'join':
      await joinChannel(positional, config);
      break;
      
    case 'members':
      await listMembers(positional, config);
      break;
      
    case 'invite':
      await inviteEntity(positional, config);
      break;
      
    case 'invitations':
      await listInvitations(config);
      break;
      
    default:
      console.log('Usage: fam channels <list|create|join|members|invite|invitations>');
      console.log('');
      console.log('Commands:');
      console.log('  list                      List channels');
      console.log('  create <name> [--public]  Create a channel');
      console.log('  join <channel_id>         Join a channel');
      console.log('  members <channel_id>      List channel members');
      console.log('  invite <id> <entity>      Invite entity to private channel');
      console.log('  invitations               List pending invitations');
      break;
  }
}

// ============================================================================
// List Channels
// ============================================================================

async function listChannels(
  flags: Record<string, string | boolean>,
  config: CliConfig
): Promise<void> {
  const includePublic = !flags.private;
  
  const response = await entityRequest<{ channels: Channel[] }>(config, '/channels/list', {
    include_public: includePublic,
  });
  
  const channels = response.channels;
  
  if (channels.length === 0) {
    console.log('No channels found.');
    return;
  }
  
  console.log(`\nChannels (${channels.length}):\n`);
  
  for (const channel of channels) {
    const visibility = channel.is_public ? 'public' : 'private';
    console.log(`  ${channel.name} (${channel.id})`);
    console.log(`    Visibility: ${visibility}`);
    console.log(`    Created by: ${channel.created_by_entity}`);
    console.log(`    Created: ${channel.created_at}`);
    console.log('');
  }
}

// ============================================================================
// Create Channel
// ============================================================================

async function createChannel(
  positional: string[],
  flags: Record<string, string | boolean>,
  config: CliConfig
): Promise<void> {
  const name = positional[0];
  if (!name) {
    throw new Error('Usage: fam channels create <name> [--public]');
  }
  
  const isPublic = !!flags.public;
  
  console.log(`Creating channel: ${name} (${isPublic ? 'public' : 'private'})`);
  
  const response = await entityRequest<{ channel: Channel }>(config, '/channels/create', {
    name,
    is_public: isPublic,
  });
  
  console.log(`\nChannel created: ${response.channel.name} (${response.channel.id})`);
}

// ============================================================================
// Join Channel
// ============================================================================

async function joinChannel(
  positional: string[],
  config: CliConfig
): Promise<void> {
  const channelId = positional[0];
  if (!channelId) {
    throw new Error('Usage: fam channels join <channel_id>');
  }
  
  console.log(`Joining channel: ${channelId}`);
  
  await entityRequest(config, '/channels/join', { channel_id: channelId });
  
  console.log(`Joined channel successfully.`);
}

// ============================================================================
// List Members
// ============================================================================

async function listMembers(
  positional: string[],
  config: CliConfig
): Promise<void> {
  const channelId = positional[0];
  if (!channelId) {
    throw new Error('Usage: fam channels members <channel_id>');
  }
  
  const response = await entityRequest<{ members: ChannelMember[] }>(config, '/channels/list-members', {
    channel_id: channelId,
  });
  
  const members = response.members;
  
  if (members.length === 0) {
    console.log('No members in this channel.');
    return;
  }
  
  console.log(`\nMembers (${members.length}):\n`);
  
  for (const member of members) {
    console.log(`  ${member.entity_id} (${member.role})`);
    console.log(`    Joined: ${member.joined_at}`);
  }
  console.log('');
}

// ============================================================================
// Invite Entity
// ============================================================================

async function inviteEntity(
  positional: string[],
  config: CliConfig
): Promise<void> {
  const channelId = positional[0];
  const entityId = positional[1];
  
  if (!channelId || !entityId) {
    throw new Error('Usage: fam channels invite <channel_id> <entity_id>');
  }
  
  console.log(`Inviting ${entityId} to channel ${channelId}...`);
  
  await entityRequest(config, '/channels/invite', {
    channel_id: channelId,
    invited_entity: entityId,
  });
  
  console.log(`Invitation sent.`);
}

// ============================================================================
// List Invitations
// ============================================================================

async function listInvitations(config: CliConfig): Promise<void> {
  const response = await entityRequest<{ invitations: Invitation[] }>(config, '/channels/invitations', {});
  
  const invitations = response.invitations;
  
  if (invitations.length === 0) {
    console.log('No pending invitations.');
    return;
  }
  
  console.log(`\nPending Invitations (${invitations.length}):\n`);
  
  for (const invite of invitations) {
    console.log(`  Channel: ${invite.channel_id}`);
    console.log(`  From: ${invite.invited_by}`);
    console.log(`  Created: ${invite.created_at}`);
    console.log(`  ID: ${invite.id}`);
    console.log('');
  }
}
