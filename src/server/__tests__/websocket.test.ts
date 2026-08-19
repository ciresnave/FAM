import { test, expect, describe, beforeEach, afterEach } from 'bun:test';
import { Database } from 'bun:sqlite';
import { createContext } from '../../db/transaction';
import { initializeDatabase } from '../../db/schema';
import { AccountRepository } from '../../db/repositories/account';
import { EntityRepository } from '../../db/repositories/entity';
import { WebSocketManager } from '../websocket';
import type { WebSocketMessage } from '../../types';

// ============================================================================
// Test Harness
// ============================================================================

function mockWs() {
  const sent: any[] = [];
  return {
    sent,
    send(data: string) { sent.push(JSON.parse(data)); },
    close() {},
  };
}

function pushFrame(from: string, to: string, text: string, messageId: number): WebSocketMessage {
  return {
    type: 'message',
    from,
    channel: null,
    to,
    text,
    timestamp: new Date().toISOString(),
    message_id: messageId,
  } as WebSocketMessage;
}

// ============================================================================
// Tests
// ============================================================================

describe('WebSocketManager availability', () => {
  let db: Database;
  let ctx: ReturnType<typeof createContext>;
  let wsManager: WebSocketManager;
  let entities: EntityRepository;

  const ACCOUNT = 'ws.example.com';
  const A = 'a@ws.example.com';
  const B = 'b@ws.example.com';

  beforeEach(() => {
    db = new Database(':memory:');
    initializeDatabase(db);
    ctx = createContext(db);
    wsManager = new WebSocketManager(ctx);
    entities = ctx.entities;

    const accounts = new AccountRepository(db);
    accounts.create(ACCOUNT, 'Test');
    entities.create(A, ACCOUNT, 'agent', 'pk-a');
    entities.create(B, ACCOUNT, 'agent', 'pk-b');
  });

  afterEach(() => {
    wsManager.shutdown();
    db.close();
  });

  function connect(entityId: string) {
    const session = ctx.sessions.create(entityId);
    const ws = mockWs();
    wsManager.handleConnection(ws, entityId, session.id);
    // First frame is the welcome message
    expect(ws.sent[0].type).toBe('message');
    return ws;
  }

  test('pushToEntity delivers to a connected available entity', () => {
    const ws = connect(A);
    wsManager.pushToEntity(A, pushFrame(B, A, 'hello', 1));
    expect(ws.sent.filter(m => m.type === 'message').length).toBe(2); // welcome + push
  });

  test('pushToEntity suppresses pushes to an unavailable entity', () => {
    entities.updateAvailability(A, 'unavailable');
    const ws = connect(A); // welcome is sent directly, not gated
    wsManager.pushToEntity(A, pushFrame(B, A, 'gated', 1));
    expect(ws.sent.filter(m => m.type === 'message').length).toBe(1); // welcome only
  });

  test('setAvailability broadcasts the change to other connected entities', async () => {
    const wsB = connect(B);
    connect(A);

    await wsManager.setAvailability(A, 'unavailable');

    const broadcast = wsB.sent.find(m => m.type === 'availability');
    expect(broadcast).toBeDefined();
    expect(broadcast.entity_id).toBe(A);
    expect(broadcast.availability).toBe('unavailable');
  });

  test('unavailable entity queues silently; flipping to available flushes the backlog', async () => {
    const wsA = connect(A);
    const wsB = connect(B);

    // A pauses incoming
    const flushedOnPause = await wsManager.setAvailability(A, 'unavailable');
    expect(flushedOnPause).toBe(0);

    // B sends while A is unavailable: message persists, push is suppressed
    const message = await ctx.messages.sendDirectMessage(B, A, 'while you were away');
    wsManager.pushToEntity(A, pushFrame(B, A, 'while you were away', message.id));

    const pushesDuringPause = wsA.sent.filter(m => m.type === 'message' && m.message_id === message.id);
    expect(pushesDuringPause.length).toBe(0);

    // Message remains queued (not delivered)
    const undelivered = await ctx.messages.getUndelivered(A);
    expect(undelivered.length).toBe(1);

    // A resumes: backlog pushes immediately, no explicit client request
    const flushed = await wsManager.setAvailability(A, 'available');
    expect(flushed).toBe(1);

    const pushed = wsA.sent.filter(m => m.type === 'message' && m.message_id === message.id);
    expect(pushed.length).toBe(1);
    expect(pushed[0].text).toBe('while you were away');

    // Availability resume broadcast also reached B
    const resume = wsB.sent.filter(m => m.type === 'availability');
    expect(resume.length).toBe(2); // unavailable + available
    expect(resume[1].availability).toBe('available');

    // Flushed messages are NOT marked delivered by the server — client acks
    const stillUndelivered = await ctx.messages.getUndelivered(A);
    expect(stillUndelivered.length).toBe(1);
  });

  test('flush is a no-op for an entity with no connections (messages stay queued)', async () => {
    await ctx.messages.sendDirectMessage(B, A, 'offline queue');

    const pushed = await wsManager.flushUndeliveredMessages(A);
    expect(pushed).toBe(0);

    const undelivered = await ctx.messages.getUndelivered(A);
    expect(undelivered.length).toBe(1);
  });

  test('welcome message still delivered on connect while unavailable', () => {
    entities.updateAvailability(A, 'unavailable');
    const ws = connect(A);
    // Connection confirmation is not an incoming message — always sent
    expect(ws.sent.length).toBe(1);
    expect(ws.sent[0].text).toBe('Connected to FAM server');
  });
});
