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

// ============================================================================
// Configuration
// ============================================================================

const FAM_SERVER_URL = process.env.FAM_SERVER_URL || 'http://127.0.0.1:7899';
const FAM_WS_URL = process.env.FAM_WS_URL || 'ws://127.0.0.1:7899/ws';

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

export interface SendMessageResponse {
  message_id: number;
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
  private reconnectBaseDelay = 1000;
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
    const res = await fetch(`${this.serverUrl}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    
    if (!res.ok) {
      const err = await res.text();
      throw new Error(`FAM error (${path}): ${res.status} ${err}`);
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
  async sendDirectMessage(toEntity: EntityId, text: string): Promise<SendMessageResponse> {
    return this.request<SendMessageResponse>('/messages/send', {
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
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error('[fam-client] Max reconnection attempts reached');
      return;
    }
    
    const delay = this.reconnectBaseDelay * Math.pow(2, this.reconnectAttempts);
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
          console.error('[fam-client] Re-authentication failed:', e);
          this.attemptReconnect();
        }
      } else if (this.entityId && this.sessionId) {
        // Fallback: try reconnecting with existing session
        this.connectWebSocket();
      }
    }, delay);
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
