// FAM HTTP/WebSocket Client for MCP Adapter
//
// Connects to the FAM server and provides methods for all FAM operations.

import type {
  EntityId,
  ChannelId,
  Entity,
  Channel,
  ChannelMember,
  Message,
  WebSocketMessage,
  WebSocketMessagePush,
} from '../../types';
import { base64ToBuffer } from '../../crypto/keys';
import { FAM_VERSION } from '../../utils/versioning';
import { DEFAULT_SERVER_URL, DEFAULT_WS_URL } from '../../config';

// ============================================================================
// Configuration
// ============================================================================

const FAM_SERVER_URL = process.env.FAM_SERVER_URL || DEFAULT_SERVER_URL;
const FAM_WS_URL = process.env.FAM_WS_URL || DEFAULT_WS_URL;

/** Routes that establish a session rather than consuming one. */
const SESSION_ESTABLISHING_PATHS = new Set(['/entities/connect', '/entities/authenticate']);

export class FamHttpError extends Error {
  constructor(
    public readonly path: string,
    public readonly status: number,
    body: string
  ) {
    super(`FAM error (${path}): ${status} ${body}`);
    this.name = 'FamHttpError';
  }
}

/**
 * Is retrying pointless?
 *
 * 404 — the entity no longer exists. 401/403 — this key is no longer allowed to
 * speak for it. Waiting does not fix any of those, and re-authenticating in a
 * loop against them is work the server does for nobody.
 *
 * Everything else, including 5xx, 429 and network errors, is transient: the
 * entity is presumed fine and the connection is not.
 */
export function isPermanentFailure(e: unknown): boolean {
  if (!(e instanceof FamHttpError)) return false;
  return e.status === 401 || e.status === 403 || e.status === 404;
}

const RECONNECT_BASE_DELAY_MS = 1_000;
const RECONNECT_MAX_DELAY_MS = 30_000;

/**
 * Exponential backoff, capped.
 *
 * Uncapped doubling reaches 512s by attempt 10, so the last retries are minutes
 * apart — long enough that a server which came back stays unnoticed. The cap
 * keeps late attempts useful without hammering a server that is still down.
 */
export function reconnectDelay(attempt: number): number {
  return Math.min(RECONNECT_BASE_DELAY_MS * Math.pow(2, attempt), RECONNECT_MAX_DELAY_MS);
}

// ============================================================================
// Types
// ============================================================================

export interface FamClientConfig {
  serverUrl?: string;
  wsUrl?: string;
}

export interface ConnectResponse {
  nonce: string;
}

export interface AuthenticateResponse {
  session_id: string;
  websocket_url: string;
  availability?: string;
  undelivered_messages: Array<{
    id: number;
    from_entity: string;
    to_entity: string | null;
    channel_id: string | null;
    text: string;
    sent_at: string;
    delivered: number;
  }>;
}

export interface DeliveryReport {
  /**
   * What became of the message at the moment it was sent.
   *
   *   pushed  -- written to a live socket; silence afterwards is theirs
   *   paused  -- recipient DECLARED unavailable; queued deliberately
   *   offline -- no connection; queued, seen on reconnect
   *
   * `paused` is honest-broadcast, not enforced truth: it reports what the
   * recipient said about itself, not a promise about what it will do.
   */
  outcome: 'pushed' | 'paused' | 'offline';
  recipient: {
    status: string;
    availability: string;
    queue_empty: boolean | null;
    last_state_change: string | null;
  };
  declared_by_recipient: boolean;
}

export interface SendMessageResponse {
  message_id: number;
  delivery?: DeliveryReport;
}

// ============================================================================
// FAM Client
// ============================================================================

export class FamClient {
  private serverUrl: string;
  private wsUrl: string;
  private entityId: EntityId | null = null;
  private sessionId: string | null = null;
  private ws: WebSocket | null = null;
  private messageHandlers: ((message: WebSocketMessagePush) => void)[] = [];
  private undeliveredHandlers: ((messages: AuthenticateResponse['undelivered_messages']) => void)[] = [];
  private invitationHandlers: ((invitation: { channel_id: string; channel_name: string; invited_by: string; invitation_id: string }) => void)[] = [];
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 10;
  /**
   * Set once reconnection has permanently stopped. Without this the client
   * looked identical whether it was between retries or finished forever.
   */
  private terminated: { reason: string } | null = null;
  private terminalHandlers: ((reason: string) => void)[] = [];
  private heartbeatInterval: ReturnType<typeof setInterval> | null = null;
  
  // Re-authentication credentials (stored for reconnection)
  private publicKey: string | null = null;
  private signFn: ((data: Uint8Array) => Promise<string>) | null = null;
  
  constructor(config?: FamClientConfig) {
    this.serverUrl = config?.serverUrl || FAM_SERVER_URL;
    this.wsUrl = config?.wsUrl || FAM_WS_URL;
  }
  
  /**
   * Set credentials for re-authentication on reconnect.
   */
  setAuthCredentials(publicKey: string, signFn: (data: Uint8Array) => Promise<string>): void {
    this.publicKey = publicKey;
    this.signFn = signFn;
  }
  
  // --------------------------------------------------------------------------
  // HTTP Request Helper
  // --------------------------------------------------------------------------
  
  /**
   * Make an HTTP request to the FAM server.
   */
  async request<T>(path: string, body: object): Promise<T> {
    // Entity-scoped routes derive identity from the session, so attach it to
    // every call once we have one. Routes that ESTABLISH a session are excluded
    // — they run before one exists.
    const payload: Record<string, unknown> = { ...body };
    if (
      this.sessionId &&
      payload.session_id === undefined &&
      !SESSION_ESTABLISHING_PATHS.has(path)
    ) {
      payload.session_id = this.sessionId;
    }

    const res = await fetch(`${this.serverUrl}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    
    if (!res.ok) {
      const err = await res.text();
      // Typed, so reconnect logic can tell "entity is gone" from "server is
      // busy" instead of parsing a status out of a message string.
      throw new FamHttpError(path, res.status, err);
    }
    
    return res.json() as Promise<T>;
  }
  
  // --------------------------------------------------------------------------
  // Entity Operations
  // --------------------------------------------------------------------------
  
  /**
   * Get nonce challenge for authentication.
   */
  async connect(entityId: EntityId, publicKey: string): Promise<ConnectResponse> {
    return this.request<ConnectResponse>('/entities/connect', {
      entity_id: entityId,
      public_key: publicKey,
    });
  }
  
  /**
   * Complete authentication with signed nonce.
   */
  async authenticate(
    entityId: EntityId,
    nonce: string,
    signature: string
  ): Promise<AuthenticateResponse> {
    const response = await this.request<AuthenticateResponse>('/entities/authenticate', {
      entity_id: entityId,
      nonce,
      signature,
    });
    
    this.entityId = entityId;
    this.sessionId = response.session_id;
    
    return response;
  }
  
  /**
   * Disconnect from the server.
   */
  async disconnect(): Promise<void> {
    if (this.entityId && this.sessionId) {
      try {
        await this.request('/entities/disconnect', {
          entity_id: this.entityId,
          session_id: this.sessionId,
        });
      } catch {
        // Best effort
      }
    }
    
    this.stopHeartbeat();
    this.ws?.close();
    this.ws = null;
    this.entityId = null;
    this.sessionId = null;
  }
  
  /**
   * Send heartbeat to keep session alive.
   */
  async heartbeat(): Promise<void> {
    if (this.entityId && this.sessionId) {
      await this.request('/entities/heartbeat', {
        entity_id: this.entityId,
        session_id: this.sessionId,
      });
    }
  }
  
  /**
   * Update entity status.
   */
  async setStatus(status: 'online' | 'away' | 'busy'): Promise<void> {
    if (this.entityId && this.sessionId) {
      await this.request('/entities/status', {
        entity_id: this.entityId,
        session_id: this.sessionId,
        status,
      });
    }
  }
  
  /**
   * Set availability (user intent: available/unavailable). Setting
   * 'unavailable' pauses incoming pushes; setting 'available' immediately
   * pushes any queued backlog.
   */
  async setAvailability(availability: 'available' | 'unavailable'): Promise<{ ok: boolean; availability: string; messages_pushed: number }> {
    if (!this.entityId || !this.sessionId) {
      throw new Error('Not authenticated');
    }
    return this.request('/entities/availability', {
      entity_id: this.entityId,
      session_id: this.sessionId,
      availability,
    });
  }
  
  /** Record a piece of work, optionally naming who owns it. */
  async createTask(input: {
    title: string;
    ref?: string | null;
    owner_entity_id?: string | null;
  }): Promise<any> {
    if (!this.entityId || !this.sessionId) throw new Error('Not authenticated');
    return this.request('/tasks/create', {
      entity_id: this.entityId,
      session_id: this.sessionId,
      ...input,
    });
  }

  /** Hand work to someone, take it yourself, or set it down with null. */
  async assignTask(taskId: string, ownerEntityId: string | null): Promise<any> {
    if (!this.entityId || !this.sessionId) throw new Error('Not authenticated');
    return this.request('/tasks/assign', {
      entity_id: this.entityId,
      session_id: this.sessionId,
      task_id: taskId,
      owner_entity_id: ownerEntityId,
    });
  }

  async closeTask(taskId: string, status: 'done' | 'cancelled'): Promise<any> {
    if (!this.entityId || !this.sessionId) throw new Error('Not authenticated');
    return this.request('/tasks/close', {
      entity_id: this.entityId,
      session_id: this.sessionId,
      task_id: taskId,
      status,
    });
  }

  async listTasks(status?: 'open' | 'done' | 'cancelled'): Promise<any> {
    if (!this.entityId || !this.sessionId) throw new Error('Not authenticated');
    return this.request('/tasks/list', {
      entity_id: this.entityId,
      session_id: this.sessionId,
      status,
    });
  }

  /**
   * Publish this session's context bag.
   *
   * Namespaced under `mcp.` because these are framework-local facts — FAM has
   * no concept of a working directory and must not acquire one. The server
   * stores the map opaquely and compares values for equality; only this adapter
   * knows what the keys mean.
   */
  async setContext(context: Record<string, string> | null): Promise<unknown> {
    if (!this.entityId || !this.sessionId) {
      throw new Error('Not authenticated');
    }
    return this.request('/entities/context', {
      entity_id: this.entityId,
      session_id: this.sessionId,
      context,
    });
  }

  /**
   * Set or clear your free-text summary of what you are currently doing.
   *
   * This is what makes you routable without anyone broadcasting: name and
   * capabilities say who you are, this says what you are on. Pass null to
   * clear it.
   *
   * RE-SET IT WHEN IT IS STILL TRUE. The stamp records when you last vouched
   * for these words, not when you last changed them, and readers use the age
   * to decide how much to trust it.
   */
  async setSummary(summary: string | null): Promise<{
    ok: boolean;
    summary: string | null;
    summary_set_at: string | null;
  }> {
    if (!this.entityId || !this.sessionId) {
      throw new Error('Not authenticated');
    }
    return this.request('/entities/summary', {
      entity_id: this.entityId,
      session_id: this.sessionId,
      summary,
    });
  }

  /**
   * Declare whether your work queue is empty.
   *
   * DECLARED state — nothing outside this process can derive it. A heartbeat
   * proves the process is alive; it cannot say whether anything is happening,
   * which is why this exists as a separate statement rather than being inferred.
   *
   * Declare it on BOTH edges. Announcing "empty" and never announcing the
   * resumption leaves you looking idle while you work; the reverse leaves you
   * looking busy forever after you stop.
   */
  async setQueueEmpty(queueEmpty: boolean): Promise<{
    ok: boolean;
    queue_empty: boolean;
    last_state_change: string | null;
  }> {
    if (!this.entityId || !this.sessionId) {
      throw new Error('Not authenticated');
    }
    return this.request('/entities/queue-state', {
      entity_id: this.entityId,
      session_id: this.sessionId,
      queue_empty: queueEmpty,
    });
  }

  /**
   * List entities with optional filters.
   */
  async listEntities(filters?: {
    type?: string;
    status?: string;
    account_id?: string;
  }): Promise<Entity[]> {
    const response = await this.request<{ entities: Entity[] }>('/entities/list', {
      entity_id: this.entityId,
      ...filters,
    });
    return response.entities;
  }
  
  // --------------------------------------------------------------------------
  // Channel Operations
  // --------------------------------------------------------------------------
  
  /**
   * Create a new channel.
   */
  async createChannel(name: string, isPublic: boolean = true): Promise<Channel> {
    const response = await this.request<{ channel: Channel }>('/channels/create', {
      entity_id: this.entityId,
      name,
      is_public: isPublic,
    });
    return response.channel;
  }
  
  /**
   * Join a channel.
   */
  async joinChannel(channelId: ChannelId): Promise<ChannelMember> {
    const response = await this.request<{ member: ChannelMember }>('/channels/join', {
      entity_id: this.entityId,
      channel_id: channelId,
    });
    return response.member;
  }
  
  /**
   * Leave a channel.
   */
  async leaveChannel(channelId: ChannelId): Promise<void> {
    await this.request('/channels/leave', {
      entity_id: this.entityId,
      channel_id: channelId,
    });
  }
  
  /**
   * List channels visible to this entity.
   */
  async listChannels(includePublic: boolean = true): Promise<Channel[]> {
    const response = await this.request<{ channels: Channel[] }>('/channels/list', {
      entity_id: this.entityId,
      include_public: includePublic,
    });
    return response.channels;
  }
  
  /**
   * List members of a channel.
   */
  async listChannelMembers(channelId: ChannelId): Promise<ChannelMember[]> {
    const response = await this.request<{ members: ChannelMember[] }>('/channels/list-members', {
      channel_id: channelId,
    });
    return response.members;
  }
  
  // --------------------------------------------------------------------------
  // Message Operations
  // --------------------------------------------------------------------------
  
  /**
   * Send a direct message.
   */
  async sendDirectMessage(
    toEntity: EntityId,
    text: string,
    refs?: Array<{ kind: string; mode: string; payload: Record<string, string> }>
  ): Promise<SendMessageResponse> {
    return this.request<SendMessageResponse>('/messages/send', {
      refs,
      entity_id: this.entityId,
      to_entity: toEntity,
      text,
    });
  }
  
  /**
   * Send a channel message.
   */
  async sendChannelMessage(channelId: ChannelId, text: string): Promise<SendMessageResponse> {
    return this.request<SendMessageResponse>('/messages/send', {
      entity_id: this.entityId,
      channel_id: channelId,
      text,
    });
  }
  
  /**
   * Mark messages as delivered.
   */
  async markDelivered(messageIds: number[]): Promise<void> {
    await this.request('/messages/delivered', {
      entity_id: this.entityId,
      message_ids: messageIds,
    });
  }
  
  /**
   * Get message history.
   */
  async getHistory(
    options: { channelId: ChannelId } | { otherEntityId: EntityId },
    limit: number = 50
  ): Promise<Message[]> {
    const response = await this.request<{ messages: Message[] }>('/messages/history', {
      entity_id: this.entityId,
      limit,
      ...options,
    });
    return response.messages;
  }
  
  // --------------------------------------------------------------------------
  // WebSocket Connection
  // --------------------------------------------------------------------------
  
  /**
   * Connect to WebSocket for real-time push notifications.
   */
  connectWebSocket(): void {
    if (!this.entityId || !this.sessionId) {
      throw new Error('Must authenticate before connecting WebSocket');
    }
    
    const url = new URL(this.wsUrl);
    url.searchParams.set('entity_id', this.entityId);
    url.searchParams.set('session_id', this.sessionId);
    // Declare our version so the server can refuse at connect rather than
    // accepting us and failing every frame.
    url.searchParams.set('version', FAM_VERSION);
    
    this.ws = new WebSocket(url.toString());
    
    this.ws.onopen = () => {
      console.error('[fam-client] WebSocket connected');
      this.reconnectAttempts = 0;
      this.startHeartbeat();
    };
    
    this.ws.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data) as WebSocketMessage;
        
        if (message.type === 'message') {
          // Notify all handlers
          for (const handler of this.messageHandlers) {
            handler(message);
          }
        } else if (message.type === 'heartbeat') {
          // Server heartbeat response
        } else if (message.type === 'availability') {
          // Presence change broadcast from another entity
          console.error(`[fam-client] Entity ${message.entity_id} is now ${message.availability}`);
        } else if (message.type === 'invitation') {
          // Invitation notification
          for (const handler of this.invitationHandlers) {
            handler({
              channel_id: message.channel_id,
              channel_name: message.channel_name,
              invited_by: message.invited_by,
              invitation_id: message.invitation_id,
            });
          }
        }
      } catch (e) {
        console.error('[fam-client] Failed to parse WebSocket message:', e);
      }
    };
    
    this.ws.onclose = () => {
      console.error('[fam-client] WebSocket disconnected');
      this.stopHeartbeat();
      this.attemptReconnect();
    };
    
    this.ws.onerror = (error) => {
      console.error('[fam-client] WebSocket error:', error);
    };
  }
  
  /**
   * Register a handler for incoming messages.
   */
  onMessage(handler: (message: WebSocketMessagePush) => void): void {
    this.messageHandlers.push(handler);
  }
  
  /**
   * Remove a message handler.
   */
  offMessage(handler: (message: WebSocketMessagePush) => void): void {
    this.messageHandlers = this.messageHandlers.filter(h => h !== handler);
  }
  
  /**
   * Register a handler for undelivered messages (received after reconnection).
   */
  onUndeliveredMessages(handler: (messages: AuthenticateResponse['undelivered_messages']) => void): void {
    this.undeliveredHandlers.push(handler);
  }
  
  /**
   * Remove an undelivered messages handler.
   */
  offUndeliveredMessages(handler: (messages: AuthenticateResponse['undelivered_messages']) => void): void {
    this.undeliveredHandlers = this.undeliveredHandlers.filter(h => h !== handler);
  }
  
  /**
   * Register a handler for channel invitation notifications.
   */
  onInvitation(handler: (invitation: { channel_id: string; channel_name: string; invited_by: string; invitation_id: string }) => void): void {
    this.invitationHandlers.push(handler);
  }
  
  /**
   * Remove an invitation handler.
   */
  offInvitation(handler: (invitation: { channel_id: string; channel_name: string; invited_by: string; invitation_id: string }) => void): void {
    this.invitationHandlers = this.invitationHandlers.filter(h => h !== handler);
  }
  
  /**
   * Dispatch undelivered messages to registered handlers.
   * Used after initial authentication (reconnect path dispatches automatically).
   */
  dispatchUndelivered(messages: AuthenticateResponse['undelivered_messages']): void {
    if (messages.length === 0) return;
    for (const handler of this.undeliveredHandlers) {
      handler(messages);
    }
  }
  
  private startHeartbeat(): void {
    this.heartbeatInterval = setInterval(() => {
      if (this.ws?.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify({ type: 'heartbeat' }));
      }
    }, 30_000);
  }
  
  private stopHeartbeat(): void {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }
  }
  
  private attemptReconnect(): void {
    if (this.terminated) return;

    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      this.terminate(
        `gave up after ${this.maxReconnectAttempts} reconnection attempts`
      );
      return;
    }

    const delay = reconnectDelay(this.reconnectAttempts);
    this.reconnectAttempts++;
    
    console.error(`[fam-client] Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts})`);
    
    setTimeout(async () => {
      if (this.entityId && this.signFn && this.publicKey) {
        try {
          // Re-authenticate to get a new session
          const { nonce } = await this.connect(this.entityId, this.publicKey);
          const nonceBytes = base64ToBuffer(nonce);
          const signature = await this.signFn(nonceBytes);
          const authResponse = await this.authenticate(this.entityId, nonce, signature);
          
          // Process undelivered messages from the server
          if (authResponse.undelivered_messages && authResponse.undelivered_messages.length > 0) {
            console.error(`[fam-client] Received ${authResponse.undelivered_messages.length} undelivered messages after reconnect`);
            for (const handler of this.undeliveredHandlers) {
              handler(authResponse.undelivered_messages);
            }
          }
          
          // Connect WebSocket with new session
          this.connectWebSocket();
        } catch (e) {
          // A deleted or revoked entity will never authenticate. Retrying it
          // costs the server ten pointless auth attempts and leaves the agent
          // unusable for ~17 minutes without ever saying why.
          if (isPermanentFailure(e)) {
            this.terminate(
              e instanceof FamHttpError && e.status === 404
                ? `entity ${this.entityId} no longer exists on the server`
                : `entity ${this.entityId} is no longer authorized (${
                    e instanceof FamHttpError ? e.status : 'auth failure'
                  })`
            );
            return;
          }

          console.error('[fam-client] Re-authentication failed:', e);
          this.attemptReconnect();
        }
      } else if (this.entityId && this.sessionId) {
        // Fallback: try reconnecting with existing session
        this.connectWebSocket();
      }
    }, delay);
  }
  
  /**
   * Stop reconnecting for good and say so.
   *
   * Previously giving up wrote one console line and returned, so the consumer
   * had no way to distinguish "between retries" from "finished forever" — the
   * channel went quiet and nothing reported it.
   */
  private terminate(reason: string): void {
    if (this.terminated) return;
    this.terminated = { reason };
    this.stopHeartbeat();
    console.error(`[fam-client] Reconnection stopped: ${reason}`);
    for (const handler of this.terminalHandlers) handler(reason);
  }

  /**
   * Notified when the client stops reconnecting permanently.
   */
  onTerminalFailure(handler: (reason: string) => void): void {
    this.terminalHandlers.push(handler);
  }

  /** Why reconnection stopped, or null while still connected or retrying. */
  getTerminalReason(): string | null {
    return this.terminated?.reason ?? null;
  }

  // --------------------------------------------------------------------------
  // Getters
  // --------------------------------------------------------------------------
  
  getEntityId(): EntityId | null {
    return this.entityId;
  }
  
  getSessionId(): string | null {
    return this.sessionId;
  }
  
  isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }
}
