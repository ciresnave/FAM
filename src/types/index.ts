// FAM (Federated Agent Messaging) Type Definitions

// ============================================================================
// Account Types
// ============================================================================

export type AccountId = string; // email address

export interface Account {
  id: AccountId;
  display_name: string | null;
  created_at: string;
  updated_at: string;
  /** Identity provider that owns this account. Null only for pre-v6 rows. */
  provider: 'google' | 'github' | null;
  /** The provider's own stable user id — the authoritative identity, not the email. */
  provider_account_id: string | null;
}

// ============================================================================
// Entity Types
// ============================================================================

export type EntityId = string; // name@account
export type EntityType = 'agent' | 'human' | 'tool';

export type Availability = 'available' | 'unavailable';

export interface Entity {
  id: EntityId;
  account_id: AccountId;
  type: EntityType;
  display_name: string | null;
  capabilities: EntityCapabilities;
  location_server: string | null;
  public_key: string; // base64-encoded
  status: 'online' | 'offline' | 'away';
  /**
   * User-controlled intent, independent of connection state. 'unavailable'
   * pauses incoming message pushes (messages queue silently until flipped
   * back to 'available', at which point the backlog is pushed immediately).
   */
  availability: Availability;

  /**
   * Whether the entity has DECLARED its work queue empty.
   *
   * `null` means never declared, and that is a distinct claim from `false`: an
   * entity that has not spoken has made no statement, and reading that as
   * "busy" invents one. Only the entity can set this — nothing external can
   * derive whether it has work queued, which is the whole reason it exists.
   *
   * NEVER READ IT ALONE. `false` means working OR died mid-task; the reading
   * is a triple with `last_state_change` and session liveness. See
   * EntityRepository.updateQueueEmpty.
   */
  queue_empty: boolean | null;

  /**
   * When this entity last DECLARED a change to `availability` or
   * `queue_empty`. Null until it declares something.
   *
   * Deliberately NOT a liveness signal, and deliberately not `last_seen`. A
   * heartbeat says a process is breathing; it cannot say whether anything is
   * happening — in one sweep of the peer network all 17 agents heartbeated
   * within 9.5 seconds of each other while two had been idle for hours.
   *
   * It records a CHANGE: re-declaring the same value does not move it, or an
   * agent looping on one state would look perpetually fresh.
   */
  last_state_change: string | null;

  /**
   * Free-text statement of what this entity is currently doing.
   *
   * Identity is `display_name` + `capabilities`; this is INTENT, which is what
   * routing actually needs. Null until the entity says something.
   */
  summary: string | null;

  /**
   * When the summary was last ASSERTED — not when the entity was last seen.
   *
   * Refreshed by every assertion including a repeat of the same text, because
   * staleness asks when someone last vouched for those words. Deliberately
   * opposite to `last_state_change`, which records a change and ignores
   * repeats, and emphatically not `last_seen`: a live process can carry a
   * six-month-old summary, and reporting its connection time as the summary's
   * age is the exact misreading this field exists to prevent.
   */
  summary_set_at: string | null;

  created_at: string;
  last_seen: string | null;
}

export interface EntityCapabilities {
  can_send: boolean;
  can_join_channel: boolean;
  can_create_entities: boolean;
  can_create_channels: boolean;
  can_manage_entities: boolean;
  encrypt_messages: boolean;
  [key: string]: boolean;
}

// ============================================================================
// Channel Types
// ============================================================================

export type ChannelId = string; // UUID

export interface Channel {
  id: ChannelId;
  name: string;
  created_by_entity: EntityId;
  is_public: boolean;
  created_at: string;
}

export type ChannelMemberRole = 'owner' | 'admin' | 'member';

export interface ChannelMember {
  channel_id: ChannelId;
  entity_id: EntityId;
  role: ChannelMemberRole;
  joined_at: string;
}

// ============================================================================
// Message Types
// ============================================================================

export interface Message {
  id: number;
  channel_id: ChannelId | null;
  from_entity: EntityId;
  to_entity: EntityId | null;
  text: string;
  sent_at: string;
  // NOTE: there is deliberately no `delivered` field.
  //
  // The `messages.delivered` COLUMN still exists — migration v7's backfill
  // reads it, and SQLite cannot drop a column cheaply — but nothing has
  // written it since v7. Delivery is per (message, recipient) and lives in
  // `message_deliveries`; a single flag on the message cannot answer it,
  // because a channel message is delivered to some members and not others at
  // the same time.
  //
  // It is omitted from the type so the compiler refuses reads rather than a
  // comment asking people not to. The CLI history view rendered
  // "[undelivered]" from that column and would have marked every message
  // undelivered forever — that is the bug this omission prevents recurring.
  // Ask `message_deliveries` (getUndelivered / getUndeliveredCount) instead.
}

// ============================================================================
// Authorization Types
// ============================================================================

export interface Authorization {
  id: string;
  account_id: AccountId;
  server_id: string;
  token_hash: string;
  granted_at: string;
  expires_at: string | null;
  revoked_at: string | null;
}

// ============================================================================
// Encrypted Key File Format
// ============================================================================

export interface EncryptedKeyFile {
  /**
   * FAM semver that produced this key file. Absent on legacy (pre-versioning)
   * files — readers must treat absence as compatible.
   */
  version?: string;
  entity_id: EntityId;
  public_key: string; // base64-encoded
  encrypted_private_key: string; // base64-encoded
  kdf: 'argon2id';
  kdf_params: KdfParams;
  encryption: 'aes-256-gcm';
}

export interface KdfParams {
  memory: number;
  iterations: number;
  parallelism: number;
  salt: string; // base64-encoded
}

// ============================================================================
// API Request/Response Types
// ============================================================================

// Account endpoints
export interface AuthorizeRequest {
  code: string;
  provider: 'google' | 'github';
}

export interface AuthorizeResponse {
  account_id: AccountId;
  token: string;
}

export interface CreateEntityRequest {
  account_token: string;
  name: string;
  type: EntityType;
  capabilities?: Partial<EntityCapabilities>;
}

export interface CreateEntityResponse {
  entity_id: EntityId;
  encrypted_key_file: EncryptedKeyFile;
}

export interface ListEntitiesRequest {
  account_token: string;
}

export interface ListEntitiesResponse {
  entities: Entity[];
}

export interface RevokeEntityRequest {
  account_token: string;
  entity_id: EntityId;
}

// Entity endpoints
export interface ConnectRequest {
  entity_id: EntityId;
  public_key: string; // base64-encoded
}

export interface ConnectChallenge {
  nonce: string; // base64-encoded random nonce
}

export interface ConnectResponse {
  session_id: string;
  websocket_url: string;
}

export interface DisconnectRequest {
  entity_id: EntityId;
  session_id: string;
}

export interface SetStatusRequest {
  entity_id: EntityId;
  status: string;
}

export interface SetAvailabilityRequest {
  entity_id: EntityId;
  session_id: string;
  availability: Availability;
}

export interface ListEntitiesOnlineRequest {
  scope?: 'all' | 'channel' | 'directory';
  channel_id?: ChannelId;
}

export interface SubscribeRequest {
  entity_id: EntityId;
  webhook_url?: string;
}

// Channel endpoints
export interface CreateChannelRequest {
  entity_id: EntityId;
  name: string;
  is_public?: boolean;
}

export interface JoinChannelRequest {
  entity_id: EntityId;
  channel_id: ChannelId;
}

export interface LeaveChannelRequest {
  entity_id: EntityId;
  channel_id: ChannelId;
}

export interface ListChannelsRequest {
  entity_id: EntityId;
  include_public?: boolean;
}

export interface ListChannelMembersRequest {
  channel_id: ChannelId;
}

// Message endpoints
export interface SendMessageRequest {
  entity_id: EntityId;
  channel_id?: ChannelId;
  to_entity?: EntityId;
  text: string;
}

export interface SendMessageResponse {
  message_id: number;
}

// Health endpoint
export interface HealthResponse {
  status: 'ok' | 'error';
  entities: number;
  channels: number;
  messages: number;
}

// ============================================================================
// WebSocket Message Types
// ============================================================================

export type WebSocketMessage =
  | WebSocketMessagePush
  | WebSocketMessageSend
  | WebSocketMessageHeartbeat
  | WebSocketMessageAck
  | WebSocketMessageInvitation
  | WebSocketMessageAvailability;

export interface WebSocketMessagePush {
  type: 'message';
  from: EntityId;
  channel: ChannelId | null;
  to: EntityId | null;
  text: string;
  timestamp: string;
  message_id: number;
}

export interface WebSocketMessageSend {
  type: 'send';
  to?: EntityId;
  channel?: ChannelId;
  text: string;
}

export interface WebSocketMessageHeartbeat {
  type: 'heartbeat';
}

export interface WebSocketMessageAck {
  type: 'ack';
  message_id: number;
}

export interface WebSocketMessageInvitation {
  type: 'invitation';
  channel_id: ChannelId;
  channel_name: string;
  invited_by: EntityId;
  invited_entity: EntityId;
  invitation_id: string;
  timestamp: string;
}

/**
 * Broadcast to all connected entities when an entity's availability changes,
 * so clients can update presence UI. Server → clients only.
 */
export interface WebSocketMessageAvailability {
  type: 'availability';
  entity_id: EntityId;
  availability: Availability;
  timestamp: string;
}

// ============================================================================
// Grants & Permissions
// ============================================================================

/**
 * Capabilities attached to a grant. Absent keys default to allowed.
 */
export interface GrantCapabilities {
  can_send?: boolean;
}

/**
 * A grant gives one account (grantee) permission to message a specific
 * entity owned by another account (grantor). Cross-account DMs are
 * default-deny: an active grant is required.
 */
export interface Grant {
  id: string;
  grantor_account_id: AccountId;
  grantee_account_id: AccountId;
  entity_id: EntityId;
  capabilities: GrantCapabilities;
  status: 'active' | 'revoked';
  created_at: string;
  expires_at: string | null;
  revoked_at: string | null;
}

export type PermissionTargetType = 'entity' | 'all';
export type PermissionSourceType = 'entity' | 'account';
export type PermissionAction = 'allow' | 'deny';

/**
 * A rule on an account's permission matrix. Protects the account's entities
 * (a specific one or all) from a source (a specific entity or an entire
 * account). Deny rules revoke access; allow rules override broader denies.
 */
export interface PermissionRule {
  id: string;
  account_id: AccountId;
  target_type: PermissionTargetType;
  target_entity_id: EntityId | null;
  source_type: PermissionSourceType;
  source_entity_id: EntityId | null;
  source_account_id: AccountId | null;
  action: PermissionAction;
  created_at: string;
  created_by_entity: EntityId | null;
}

// ============================================================================
// Utility Types
// ============================================================================

export type PeerId = string; // Kept for backward compatibility during migration

export interface ServerConfig {
  port: number;
  db_path: string;
  server_id: string;
  oauth_providers: {
    google?: { client_id: string; client_secret: string };
    github?: { client_id: string; client_secret: string };
  };
}
