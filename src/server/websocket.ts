// WebSocket Manager for Real-time Push Notifications

import type { DatabaseContext } from '../db/transaction';
import type { WebSocketMessage, EntityId } from '../types';
import type { MessageSendService } from './services/messageSend';
import { logger } from '../utils/logger';
import { stampVersion, assertFormatSupported, type Versioned } from '../utils/versioning';
import { entityRateLimiter } from './middleware/rateLimit';

// ============================================================================
// Configuration
// ============================================================================

const MAX_MESSAGE_LENGTH = 65536; // 64KB

// ============================================================================
// Types
// ============================================================================

interface ConnectedEntity {
  ws: any; // Bun WebSocket
  entityId: EntityId;
  sessionId: string;
  connectedAt: number;
}

// ============================================================================
// WebSocket Manager
// ============================================================================

export class WebSocketManager {
  private connections = new Map<string, ConnectedEntity>(); // sessionId -> connection
  private entityConnections = new Map<EntityId, Set<string>>(); // entityId -> sessionIds
  private wsToSession = new Map<any, string>(); // ws -> sessionId (reverse lookup)
  private ctx: DatabaseContext;
  private sendService: MessageSendService | null = null;
  
  constructor(ctx: DatabaseContext) {
    this.ctx = ctx;
  }
  
  /**
   * Bind the shared message send service.
   * Called after construction (the service needs this manager for pushes).
   */
  setSendService(service: MessageSendService): void {
    this.sendService = service;
  }
  
  // --------------------------------------------------------------------------
  // Connection Management
  // --------------------------------------------------------------------------
  
  /**
   * Handle new WebSocket connection.
   */
  handleConnection(ws: any, entityId: string, sessionId: string): void {
    // Re-validate session exists and belongs to this entity (race condition fix)
    const session = this.ctx.sessions.getById(sessionId);
    if (!session || session.entity_id !== entityId) {
      logger.warn('WebSocket connection rejected: invalid session', { entityId, sessionId });
      try { ws.close(); } catch {}
      return;
    }
    
    // Check session is still active (heartbeat within last 60 seconds)
    const lastHeartbeat = new Date(session.last_heartbeat).getTime();
    if (Date.now() - lastHeartbeat > 60 * 1000) {
      logger.warn('WebSocket connection rejected: session expired', { entityId, sessionId });
      try { ws.close(); } catch {}
      return;
    }
    
    logger.info('WebSocket connected', { entityId, sessionId });
    
    // Store connection
    const connection: ConnectedEntity = {
      ws,
      entityId,
      sessionId,
      connectedAt: Date.now(),
    };
    
    this.connections.set(sessionId, connection);
    this.wsToSession.set(ws, sessionId);
    
    // Update entity connections map
    if (!this.entityConnections.has(entityId)) {
      this.entityConnections.set(entityId, new Set());
    }
    this.entityConnections.get(entityId)!.add(sessionId);
    
    // Update session websocket ID
    this.ctx.sessions.updateWebsocketId(sessionId, sessionId);
    
    // Send welcome message
    this.send(ws, {
      type: 'message',
      from: 'system',
      channel: null,
      to: entityId,
      text: 'Connected to FAM server',
      timestamp: new Date().toISOString(),
      message_id: 0,
    });
  }
  
  /**
   * Handle WebSocket message.
   */
  async handleMessage(ws: any, rawData: string): Promise<void> {
    try {
      // Reject oversized messages
      if (rawData.length > MAX_MESSAGE_LENGTH) {
        this.send(ws, {
          type: 'message',
          from: 'system',
          channel: null,
          to: '',
          text: `Message too long: ${rawData.length} bytes (max ${MAX_MESSAGE_LENGTH})`,
          timestamp: new Date().toISOString(),
          message_id: 0,
        });
        return;
      }
      
      const message = JSON.parse(rawData) as WebSocketMessage;
      
      // Reject frames written by a newer FAM (version contract: legacy/older
      // frames accepted, newer rejected — same rule as persisted formats)
      try {
        assertFormatSupported(message as unknown as Versioned, 'WebSocket frame');
      } catch (e) {
        this.send(ws, {
          type: 'message',
          from: 'system',
          channel: null,
          to: '',
          text: e instanceof Error ? e.message : 'Unsupported frame version',
          timestamp: new Date().toISOString(),
          message_id: 0,
        });
        return;
      }
      
      switch (message.type) {
        case 'send':
          await this.handleSendMessage(ws, message);
          break;
        case 'heartbeat':
          this.handleHeartbeat(ws);
          break;
        default:
          this.send(ws, {
            type: 'message',
            from: 'system',
            channel: null,
            to: '',
            text: `Unknown message type: ${(message as any).type}`,
            timestamp: new Date().toISOString(),
            message_id: 0,
          });
      }
    } catch (e) {
      logger.error('Failed to parse WebSocket message', { error: e });
      this.send(ws, {
        type: 'message',
        from: 'system',
        channel: null,
        to: '',
        text: 'Invalid message format',
        timestamp: new Date().toISOString(),
        message_id: 0,
      });
    }
  }
  
  /**
   * Handle WebSocket close.
   */
  handleClose(ws: any): void {
    const connection = this.findConnectionByWs(ws);
    if (!connection) return;
    
    logger.info('WebSocket disconnected', { entityId: connection.entityId, sessionId: connection.sessionId });
    
    // Remove from maps
    this.connections.delete(connection.sessionId);
    this.wsToSession.delete(ws);
    const entitySessions = this.entityConnections.get(connection.entityId);
    if (entitySessions) {
      entitySessions.delete(connection.sessionId);
      if (entitySessions.size === 0) {
        this.entityConnections.delete(connection.entityId);
      }
    }
    
    // Update entity status if no other connections
    const hasOtherConnections = this.entityConnections.has(connection.entityId);
    if (!hasOtherConnections) {
      this.ctx.entities.updateStatus(connection.entityId, 'offline');
    }
  }
  
  // --------------------------------------------------------------------------
  // Message Sending
  // --------------------------------------------------------------------------
  
  /**
   * Send a message to a specific entity (all connections).
   * Availability gate: pushes to 'unavailable' entities are suppressed —
   * the message stays queued (delivered=0) and is flushed when the entity
   * flips back to 'available'. This gate applies to ALL pushes (DMs, channel
   * messages, system notifications) since it is the user's "pause incoming"
   * intent.
   */
  pushToEntity(entityId: EntityId, message: WebSocketMessage): void {
    const sessionIds = this.entityConnections.get(entityId);
    if (!sessionIds || sessionIds.size === 0) {
      // Entity is offline - message will be queued in database
      return;
    }

    // Suppress pushes to unavailable entities (silent queue)
    const entity = this.ctx.entities.getById(entityId);
    if (!entity || entity.availability === 'unavailable') {
      return;
    }

    // Send to all connections for this entity
    for (const sessionId of sessionIds) {
      const connection = this.connections.get(sessionId);
      if (connection) {
        this.send(connection.ws, message);
      }
    }
  }
  
  /**
   * Send a message to all connected entities.
   */
  broadcast(message: WebSocketMessage, excludeEntityId?: EntityId): void {
    for (const [sessionId, connection] of this.connections) {
      if (excludeEntityId && connection.entityId === excludeEntityId) {
        continue;
      }
      this.send(connection.ws, message);
    }
  }

  // --------------------------------------------------------------------------
  // Availability
  // --------------------------------------------------------------------------

  /**
   * Set an entity's availability (user intent), broadcast the change to all
   * connected entities, and — when flipping back to 'available' — immediately
   * push the queued message backlog to the entity if connected.
   *
   * Queued messages are NOT marked delivered on flush: the client acknowledges
   * via /messages/delivered after processing (at-least-once semantics).
   * Returns the number of queued messages pushed.
   */
  async setAvailability(entityId: EntityId, availability: 'available' | 'unavailable'): Promise<number> {
    this.ctx.entities.updateAvailability(entityId, availability);

    // Notify all connected entities so clients can update presence UI
    // (broadcast is direct-send, not gated by recipient availability)
    this.broadcast({
      type: 'availability',
      entity_id: entityId,
      availability,
      timestamp: new Date().toISOString(),
    });

    if (availability === 'available') {
      return this.flushUndeliveredMessages(entityId);
    }
    return 0;
  }

  /**
   * Push all queued (undelivered) messages for an entity over its active
   * connections. No-op when the entity has no connections (messages remain
   * queued for the next authenticate or flush). Returns messages pushed.
   */
  async flushUndeliveredMessages(entityId: EntityId, limit: number = 50): Promise<number> {
    const sessionIds = this.entityConnections.get(entityId);
    if (!sessionIds || sessionIds.size === 0) return 0;

    const queued = await this.ctx.messages.getUndelivered(entityId, limit);
    for (const message of queued) {
      this.pushToEntity(entityId, {
        type: 'message',
        from: message.from_entity,
        channel: message.channel_id,
        to: message.to_entity,
        text: message.text,
        timestamp: message.sent_at,
        message_id: message.id,
      });
    }
    return queued.length;
  }
  
  // --------------------------------------------------------------------------
  // Message Handling
  // --------------------------------------------------------------------------
  
  private async handleSendMessage(ws: any, message: { to?: string; channel?: string; text: string }): Promise<void> {
    const connection = this.findConnectionByWs(ws);
    if (!connection) return;
    
    const { entityId } = connection;
    
    // Rate limiting (transport-level concern, applied before delegating)
    try {
      entityRateLimiter.check(entityId);
    } catch {
      this.send(ws, {
        type: 'message',
        from: 'system',
        channel: null,
        to: entityId,
        text: 'Rate limit exceeded. Please slow down.',
        timestamp: new Date().toISOString(),
        message_id: 0,
      });
      return;
    }
    
    if (!message.text?.trim()) {
      this.send(ws, {
        type: 'message',
        from: 'system',
        channel: null,
        to: entityId,
        text: 'Message text is required',
        timestamp: new Date().toISOString(),
        message_id: 0,
      });
      return;
    }
    
    if (!message.to && !message.channel) {
      this.send(ws, {
        type: 'message',
        from: 'system',
        channel: null,
        to: entityId,
        text: 'Either "to" or "channel" must be specified',
        timestamp: new Date().toISOString(),
        message_id: 0,
      });
      return;
    }
    
    if (!this.sendService) {
      logger.error('MessageSendService not bound to WebSocketManager');
      this.send(ws, {
        type: 'message',
        from: 'system',
        channel: null,
        to: entityId,
        text: 'Send service unavailable',
        timestamp: new Date().toISOString(),
        message_id: 0,
      });
      return;
    }
    
    try {
      const sent = message.to
        ? await this.sendService.sendDirectMessage(entityId, message.to, message.text.trim())
        : await this.sendService.sendChannelMessage(entityId, message.channel!, message.text.trim());
      
      // Send acknowledgment with actual message ID
      this.send(ws, {
        type: 'ack',
        message_id: sent.id,
      });
    } catch (e) {
      logger.error('Failed to send message', { entityId, error: e });
      this.send(ws, {
        type: 'message',
        from: 'system',
        channel: null,
        to: entityId,
        text: `Failed to send message: ${e instanceof Error ? e.message : String(e)}`,
        timestamp: new Date().toISOString(),
        message_id: 0,
      });
    }
  }
  
  private handleHeartbeat(ws: any): void {
    const connection = this.findConnectionByWs(ws);
    if (!connection) return;
    
    // Update session heartbeat
    this.ctx.sessions.updateHeartbeat(connection.sessionId);
    
    // Send heartbeat response
    this.send(ws, { type: 'heartbeat' });
  }
  
  // --------------------------------------------------------------------------
  // Utility Methods
  // --------------------------------------------------------------------------
  
  private send(ws: any, message: any): void {
    try {
      // All outgoing frames carry the format version; clients ignore unknown fields
      ws.send(JSON.stringify(stampVersion(message)));
    } catch (e) {
      logger.error('Failed to send WebSocket message', { error: e });
    }
  }
  
  private findConnectionByWs(ws: any): ConnectedEntity | undefined {
    const sessionId = this.wsToSession.get(ws);
    if (!sessionId) return undefined;
    return this.connections.get(sessionId);
  }
  
  // --------------------------------------------------------------------------
  // Statistics
  // --------------------------------------------------------------------------
  
  getConnectedEntityCount(): number {
    return this.entityConnections.size;
  }
  
  getConnectionCount(): number {
    return this.connections.size;
  }
  
  getEntityConnections(entityId: EntityId): number {
    return this.entityConnections.get(entityId)?.size ?? 0;
  }
  
  // --------------------------------------------------------------------------
  // Shutdown
  // --------------------------------------------------------------------------
  
  shutdown(): void {
    // Close all connections
    for (const [sessionId, connection] of this.connections) {
      try {
        connection.ws.close();
      } catch (e) {
        // Ignore errors during shutdown
      }
    }
    
    this.connections.clear();
    this.entityConnections.clear();
    this.wsToSession.clear();
  }
}
