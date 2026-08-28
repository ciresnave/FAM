import { test, expect, describe, beforeEach, afterEach } from 'bun:test';
import { Database } from 'bun:sqlite';
import { createContext } from '../../../db/transaction';
import { initializeDatabase } from '../../../db/schema';
import { AccountRepository } from '../../../db/repositories/account';
import { EntityRepository } from '../../../db/repositories/entity';
import { MessageSendService } from '../messageSend';
import { PermissionChecker } from '../permissionChecker';
import type { WebSocketManager } from '../../websocket';
import {
  NotFoundError,
  ForbiddenError,
  InsufficientCapabilitiesError,
  EntityNotInChannelError,
  ValidationError,
  FamError,
} from '../../../types/errors';

// ============================================================================
// Test Harness
// ============================================================================

/** Records pushToEntity calls so we can assert push behavior (parity with the
 *  previous inline HTTP/WS push logic). */
class RecordingWsManager {
  pushes: Array<{ entityId: string; message: any }> = [];

  pushToEntity(entityId: string, message: any): void {
    this.pushes.push({ entityId, message });
  }
}

describe('MessageSendService', () => {
  let db: Database;
  let ctx: ReturnType<typeof createContext>;
  let service: MessageSendService;
  let wsManager: RecordingWsManager;
  let entities: EntityRepository;

  const SENDER = 'sender@svc.example.com';
  const RECEIVER = 'receiver@svc.example.com';
  const OUTSIDER = 'outsider@svc.example.com';
  const ACCOUNT = 'svc.example.com';

  beforeEach(() => {
    db = new Database(':memory:');
    initializeDatabase(db);
    ctx = createContext(db);
    wsManager = new RecordingWsManager();
    // Cast: the service only uses pushToEntity
    service = new MessageSendService(ctx, wsManager as unknown as WebSocketManager, new PermissionChecker(ctx));
    entities = ctx.entities;

    const accounts = new AccountRepository(db);
    accounts.create(ACCOUNT, 'Test');
    entities.create(SENDER, ACCOUNT, 'agent', 'pk-1');
    entities.create(RECEIVER, ACCOUNT, 'agent', 'pk-2');
    entities.create(OUTSIDER, ACCOUNT, 'agent', 'pk-3');
  });

  afterEach(() => {
    db.close();
  });

  // -- Direct messages -------------------------------------------------------

  test('persists and pushes a direct message', async () => {
    const message = (await service.sendDirectMessage(SENDER, RECEIVER, 'hello dm')).message;

    expect(message.id).toBeGreaterThan(0);
    expect(message.from_entity).toBe(SENDER);
    expect(message.to_entity).toBe(RECEIVER);
    expect(message.text).toBe('hello dm');

    // Exactly one push, to the recipient, with the persisted message metadata
    expect(wsManager.pushes.length).toBe(1);
    expect(wsManager.pushes[0]!.entityId).toBe(RECEIVER);
    expect(wsManager.pushes[0]!.message.type).toBe('message');
    expect(wsManager.pushes[0]!.message.from).toBe(SENDER);
    expect(wsManager.pushes[0]!.message.to).toBe(RECEIVER);
    expect(wsManager.pushes[0]!.message.channel).toBeNull();
    expect(wsManager.pushes[0]!.message.text).toBe('hello dm');
    expect(wsManager.pushes[0]!.message.message_id).toBe(message.id);
    expect(wsManager.pushes[0]!.message.timestamp).toBe(message.sent_at);
  });

  test('trims whitespace from message text', async () => {
    const message = (await service.sendDirectMessage(SENDER, RECEIVER, '  padded  ')).message;
    expect(message.text).toBe('padded');
    expect(wsManager.pushes[0]!.message.text).toBe('padded');
  });

  test('throws NotFoundError for unknown sender', async () => {
    try {
      await service.sendDirectMessage('ghost@svc.example.com', RECEIVER, 'hi');
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(NotFoundError);
      expect((e as NotFoundError).statusCode).toBe(404);
    }
  });

  test('throws NotFoundError for unknown recipient', async () => {
    try {
      await service.sendDirectMessage(SENDER, 'ghost@svc.example.com', 'hi');
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(NotFoundError);
    }
  });

  test('throws InsufficientCapabilitiesError when sender lacks can_send', async () => {
    entities.create('mute@svc.example.com', ACCOUNT, 'tool', 'pk-4', undefined, { can_send: false });
    try {
      await service.sendDirectMessage('mute@svc.example.com', RECEIVER, 'hi');
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(InsufficientCapabilitiesError);
      expect((e as InsufficientCapabilitiesError).statusCode).toBe(403);
    }
  });

  test('throws ValidationError for empty text', async () => {
    try {
      await service.sendDirectMessage(SENDER, RECEIVER, '   ');
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(ValidationError);
    }
  });

  test('throws ValidationError for invalid entity IDs', async () => {
    try {
      await service.sendDirectMessage('not a valid id!', RECEIVER, 'hi');
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(ValidationError);
    }
  });

  // -- Channel messages ------------------------------------------------------

  test('persists once and pushes to all members except sender', async () => {
    const ctx = createContext(db);
    const channel = ctx.channels.create('svc-room', SENDER, true);
    ctx.channels.addMember(channel.id, RECEIVER);
    ctx.channels.addMember(channel.id, OUTSIDER);

    const message = (await service.sendChannelMessage(SENDER, channel.id, 'hello room')).message;

    expect(message.id).toBeGreaterThan(0);
    expect(message.channel_id).toBe(channel.id);
    expect(message.text).toBe('hello room');

    const pushedTo = wsManager.pushes.map(p => p.entityId).sort();
    expect(pushedTo).toEqual([OUTSIDER, RECEIVER].sort());

    for (const push of wsManager.pushes) {
      expect(push.message.channel).toBe(channel.id);
      expect(push.message.from).toBe(SENDER);
      expect(push.message.message_id).toBe(message.id);
      expect(push.message.timestamp).toBe(message.sent_at);
    }
  });

  test('throws NotFoundError for unknown channel', async () => {
    try {
      await service.sendChannelMessage(SENDER, 'not-a-uuid', 'hi');
      throw new Error('should have thrown');
    } catch (e) {
      // Invalid UUID is a validation error before existence check
      expect(e).toBeInstanceOf(FamError);
    }
  });

  test('throws NotFoundError for nonexistent-but-valid channel UUID', async () => {
    const uuid = '123e4567-e89b-42d3-a456-426614174000';
    try {
      await service.sendChannelMessage(SENDER, uuid, 'hi');
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(NotFoundError);
      expect((e as NotFoundError).statusCode).toBe(404);
    }
  });

  test('throws EntityNotInChannelError for non-member sender', async () => {
    const ctx = createContext(db);
    const channel = ctx.channels.create('svc-room-2', SENDER, true);
    // OUTSIDER never joined
    try {
      await service.sendChannelMessage(OUTSIDER, channel.id, 'hi');
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(EntityNotInChannelError);
    }
  });

  // -- Cross-account permissions (default-deny + grants) ----------------------

  describe('cross-account permissions', () => {
    const FOREIGN_ACCOUNT = 'foreign.example.com';
    const FOREIGN_SENDER = 'fsender@foreign.example.com';
    const FOREIGN_MEMBER = 'fmember@foreign.example.com';

    beforeEach(() => {
      ctx.accounts.create(FOREIGN_ACCOUNT, 'Foreign');
      entities.create(FOREIGN_SENDER, FOREIGN_ACCOUNT, 'agent', 'fpk-1');
      entities.create(FOREIGN_MEMBER, FOREIGN_ACCOUNT, 'agent', 'fpk-2');
    });

    test('cross-account DM is denied without a grant', async () => {
      try {
        await service.sendDirectMessage(FOREIGN_SENDER, RECEIVER, 'hi');
        throw new Error('should have thrown');
      } catch (e) {
        expect(e).toBeInstanceOf(ForbiddenError);
      }
      // Nothing persisted or pushed
      expect(wsManager.pushes.length).toBe(0);
    });

    test('active grant allows the cross-account DM', async () => {
      ctx.grants.create(ACCOUNT, FOREIGN_ACCOUNT, RECEIVER);
      const message = (await service.sendDirectMessage(FOREIGN_SENDER, RECEIVER, 'hello across')).message;
      expect(message.id).toBeGreaterThan(0);
      expect(wsManager.pushes.length).toBe(1);
      expect(wsManager.pushes[0]!.entityId).toBe(RECEIVER);
    });

    test('revoked grant denies the DM', async () => {
      const grant = ctx.grants.create(ACCOUNT, FOREIGN_ACCOUNT, RECEIVER);
      ctx.grants.revoke(grant.id);
      try {
        await service.sendDirectMessage(FOREIGN_SENDER, RECEIVER, 'hi');
        throw new Error('should have thrown');
      } catch (e) {
        expect(e).toBeInstanceOf(ForbiddenError);
      }
    });

    test('grant for a different entity does not allow the DM', async () => {
      ctx.grants.create(ACCOUNT, FOREIGN_ACCOUNT, OUTSIDER);
      try {
        await service.sendDirectMessage(FOREIGN_SENDER, RECEIVER, 'hi');
        throw new Error('should have thrown');
      } catch (e) {
        expect(e).toBeInstanceOf(ForbiddenError);
      }
    });

    test('grant capabilities can_send=false denies the DM', async () => {
      ctx.grants.create(ACCOUNT, FOREIGN_ACCOUNT, RECEIVER, { can_send: false });
      try {
        await service.sendDirectMessage(FOREIGN_SENDER, RECEIVER, 'hi');
        throw new Error('should have thrown');
      } catch (e) {
        expect(e).toBeInstanceOf(ForbiddenError);
      }
    });

    test('deny rule on target account overrides the grant', async () => {
      ctx.grants.create(ACCOUNT, FOREIGN_ACCOUNT, RECEIVER);
      ctx.permissions.create({
        account_id: ACCOUNT,
        target_type: 'entity',
        target_entity_id: RECEIVER,
        source_type: 'entity',
        source_entity_id: FOREIGN_SENDER,
        action: 'deny',
      });
      try {
        await service.sendDirectMessage(FOREIGN_SENDER, RECEIVER, 'hi');
        throw new Error('should have thrown');
      } catch (e) {
        expect(e).toBeInstanceOf(ForbiddenError);
      }
    });

    test('deny-all-from-account rule blocks every entity of that account', async () => {
      ctx.grants.create(ACCOUNT, FOREIGN_ACCOUNT, RECEIVER);
      ctx.grants.create(ACCOUNT, FOREIGN_ACCOUNT, OUTSIDER);
      ctx.permissions.create({
        account_id: ACCOUNT,
        target_type: 'all',
        source_type: 'account',
        source_account_id: FOREIGN_ACCOUNT,
        action: 'deny',
      });
      await expect(service.sendDirectMessage(FOREIGN_SENDER, RECEIVER, 'hi')).rejects.toBeInstanceOf(ForbiddenError);
      await expect(service.sendDirectMessage(FOREIGN_SENDER, OUTSIDER, 'hi')).rejects.toBeInstanceOf(ForbiddenError);
    });

    test('specific allow rule overrides broader account-level deny', async () => {
      ctx.grants.create(ACCOUNT, FOREIGN_ACCOUNT, RECEIVER);
      // Broad deny: all targets, account source
      ctx.permissions.create({
        account_id: ACCOUNT,
        target_type: 'all',
        source_type: 'account',
        source_account_id: FOREIGN_ACCOUNT,
        action: 'deny',
      });
      // Specific allow for this sender → RECEIVER (specificity 3 beats 0)
      ctx.permissions.create({
        account_id: ACCOUNT,
        target_type: 'entity',
        target_entity_id: RECEIVER,
        source_type: 'entity',
        source_entity_id: FOREIGN_SENDER,
        action: 'allow',
      });

      const message = (await service.sendDirectMessage(FOREIGN_SENDER, RECEIVER, 'still allowed')).message;
      expect(message.id).toBeGreaterThan(0);
    });

    test('same-account deny rule blocks the DM (no grant needed for deny)', async () => {
      // SENDER and RECEIVER share ACCOUNT; deny just SENDER
      ctx.permissions.create({
        account_id: ACCOUNT,
        target_type: 'entity',
        target_entity_id: RECEIVER,
        source_type: 'entity',
        source_entity_id: SENDER,
        action: 'deny',
      });
      try {
        await service.sendDirectMessage(SENDER, RECEIVER, 'hi');
        throw new Error('should have thrown');
      } catch (e) {
        expect(e).toBeInstanceOf(ForbiddenError);
      }
      // OUTSIDER (same account) unaffected
      const ok = (await service.sendDirectMessage(OUTSIDER, RECEIVER, 'still ok')).message;
      expect(ok.id).toBeGreaterThan(0);
    });

    test('channel membership implies allow, but deny rules filter pushes', async () => {
      // Cross-account member joins the channel (membership = grant)
      const channel = ctx.channels.create('x-room', SENDER, true);
      ctx.channels.addMember(channel.id, RECEIVER);
      ctx.channels.addMember(channel.id, FOREIGN_MEMBER);

      const message = (await service.sendChannelMessage(SENDER, channel.id, 'hello room')).message;
      expect(message.id).toBeGreaterThan(0);

      // Both members received the push
      expect(wsManager.pushes.map(p => p.entityId).sort()).toEqual([FOREIGN_MEMBER, RECEIVER].sort());

      // Now RECEIVER's account denies SENDER by rule → next send skips RECEIVER's push
      wsManager.pushes.length = 0;
      ctx.permissions.create({
        account_id: ACCOUNT,
        target_type: 'all',
        source_type: 'entity',
        source_entity_id: SENDER,
        action: 'deny',
      });

      const message2 = (await service.sendChannelMessage(SENDER, channel.id, 'again')).message;
      expect(message2.id).toBeGreaterThan(0); // still persisted — channel sends are not blocked
      expect(wsManager.pushes.map(p => p.entityId)).toEqual([FOREIGN_MEMBER]); // RECEIVER filtered
    });
  });
});
