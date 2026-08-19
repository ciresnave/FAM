// MCP Tool Definitions for FAM
//
// Defines the tools exposed by the FAM MCP server.

export const FAM_TOOLS = [
  {
    name: 'fam_list_entities',
    description:
      'List entities (agents, humans, tools) connected to the FAM network. Returns their ID, type, status, and capabilities.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        type: {
          type: 'string' as const,
          enum: ['agent', 'human', 'tool'],
          description: 'Filter by entity type',
        },
        status: {
          type: 'string' as const,
          enum: ['online', 'offline', 'away', 'busy'],
          description: 'Filter by entity status',
        },
      },
    },
  },
  {
    name: 'fam_send_message',
    description:
      'Send a message to another entity. Can be a direct message (DM) or a channel message.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        to_entity: {
          type: 'string' as const,
          description: 'Entity ID to send a direct message to (e.g., "AgentName@email.com")',
        },
        channel_id: {
          type: 'string' as const,
          description: 'Channel ID to send a message to (mutually exclusive with to_entity)',
        },
        text: {
          type: 'string' as const,
          description: 'The message text to send',
        },
      },
      required: ['text'],
    },
  },
  {
    name: 'fam_create_channel',
    description: 'Create a new communication channel.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: {
          type: 'string' as const,
          description: 'Channel name (alphanumeric, hyphens, underscores)',
        },
        is_public: {
          type: 'boolean' as const,
          description: 'Whether the channel is public (default: true)',
        },
      },
      required: ['name'],
    },
  },
  {
    name: 'fam_join_channel',
    description: 'Join an existing channel.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        channel_id: {
          type: 'string' as const,
          description: 'Channel ID to join',
        },
      },
      required: ['channel_id'],
    },
  },
  {
    name: 'fam_list_channels',
    description: 'List channels visible to this entity.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        include_public: {
          type: 'boolean' as const,
          description: 'Include public channels (default: true)',
        },
      },
    },
  },
  {
    name: 'fam_list_channel_members',
    description: 'List members of a channel.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        channel_id: {
          type: 'string' as const,
          description: 'Channel ID to list members for',
        },
      },
      required: ['channel_id'],
    },
  },
  {
    name: 'fam_get_history',
    description: 'Get message history for a channel or direct message conversation.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        channel_id: {
          type: 'string' as const,
          description: 'Channel ID to get history for (mutually exclusive with other_entity_id)',
        },
        other_entity_id: {
          type: 'string' as const,
          description: 'Entity ID to get DM history with (mutually exclusive with channel_id)',
        },
        limit: {
          type: 'number' as const,
          description: 'Maximum number of messages to return (default: 50)',
        },
      },
    },
  },
  {
    name: 'fam_set_status',
    description: 'Update your status (online, away, busy).',
    inputSchema: {
      type: 'object' as const,
      properties: {
        status: {
          type: 'string' as const,
          enum: ['online', 'away', 'busy'],
          description: 'Your new status',
        },
      },
      required: ['status'],
    },
  },
  {
    name: 'fam_set_availability',
    description:
      'Set your availability (available/unavailable). Unavailable pauses ALL incoming message pushes (messages queue silently and are delivered when you become available again). Use this to focus on a task without interruption.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        availability: {
          type: 'string' as const,
          enum: ['available', 'unavailable'],
          description: 'Your new availability',
        },
      },
      required: ['availability'],
    },
  },
  {
    name: 'fam_kick_member',
    description: 'Kick a member from a channel (requires admin/owner role). The member may rejoin.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        channel_id: {
          type: 'string' as const,
          description: 'Channel ID to kick from',
        },
        target_entity: {
          type: 'string' as const,
          description: 'Entity ID to kick',
        },
      },
      required: ['channel_id', 'target_entity'],
    },
  },
  {
    name: 'fam_set_member_role',
    description: 'Set a member\'s role in a channel (requires owner role).',
    inputSchema: {
      type: 'object' as const,
      properties: {
        channel_id: {
          type: 'string' as const,
          description: 'Channel ID',
        },
        target_entity: {
          type: 'string' as const,
          description: 'Entity ID to set role for',
        },
        role: {
          type: 'string' as const,
          enum: ['admin', 'member'],
          description: 'New role for the member',
        },
      },
      required: ['channel_id', 'target_entity', 'role'],
    },
  },
  {
    name: 'fam_invite_to_channel',
    description: 'Invite an entity to a private channel (requires admin/owner role).',
    inputSchema: {
      type: 'object' as const,
      properties: {
        channel_id: {
          type: 'string' as const,
          description: 'Channel ID to invite to',
        },
        invited_entity: {
          type: 'string' as const,
          description: 'Entity ID to invite',
        },
      },
      required: ['channel_id', 'invited_entity'],
    },
  },
  {
    name: 'fam_list_invitations',
    description: 'List pending channel invitations for the current entity.',
    inputSchema: {
      type: 'object' as const,
      properties: {},
    },
  },
];
