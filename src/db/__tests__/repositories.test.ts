import { test, expect, describe, beforeEach, afterEach } from 'bun:test';
import { Database } from 'bun:sqlite';
import { AccountRepository } from '../repositories/account';
import { EntityRepository } from '../repositories/entity';
import { ChannelRepository } from '../repositories/channel';
import { MessageRepository } from '../repositories/message';
import { SessionRepository } from '../repositories/session';
import { InvitationRepository } from '../repositories/invitation';
import { GrantRepository } from '../repositories/grant';
import { PermissionRepository } from '../repositories/permission';
import { initializeDatabase } from '../schema';

describe('AccountRepository', () => {
  let db: Database;
  let repo: AccountRepository;

  beforeEach(() => {
    db = new Database(':memory:');
    initializeDatabase(db);
    repo = new AccountRepository(db);
  });

  afterEach(() => {
    db.close();
  });

  test('creates and retrieves account', () => {
    const account = repo.create('test@example.com', 'Test User');

    expect(account.id).toBe('test@example.com');
    expect(account.display_name).toBe('Test User');

    const retrieved = repo.getById('test@example.com');
    expect(retrieved).toBeDefined();
    expect(retrieved!.id).toBe('test@example.com');
  });

  test('checks account existence', () => {
    repo.create('test@example.com');

    expect(repo.exists('test@example.com')).toBe(true);
    expect(repo.exists('nonexistent@example.com')).toBe(false);
  });
});

describe('EntityRepository', () => {
  let db: Database;
  let repo: EntityRepository;

  beforeEach(() => {
    db = new Database(':memory:');
    initializeDatabase(db);
    repo = new EntityRepository(db);
  });

  afterEach(() => {
    db.close();
  });

  test('creates and retrieves entity', () => {
    // Create account first (FK constraint)
    const accounts = new AccountRepository(db);
    accounts.create('test@example.com', 'Test User');

    const entity = repo.create(
      'agent@test@example.com',
      'test@example.com',
      'agent',
      'base64publickey123',
      'test-agent'
    );

    expect(entity.id).toBe('agent@test@example.com');
    expect(entity.account_id).toBe('test@example.com');
    expect(entity.type).toBe('agent');
    expect(entity.display_name).toBe('test-agent');
    expect(entity.public_key).toBe('base64publickey123');

    const retrieved = repo.getById('agent@test@example.com');
    expect(retrieved).toBeDefined();
    expect(retrieved!.display_name).toBe('test-agent');
  });

  test('lists entities by account', () => {
    const accounts = new AccountRepository(db);
    accounts.create('test@example.com', 'Test User');

    repo.create('agent1@test@example.com', 'test@example.com', 'agent', 'key1', 'agent1');
    repo.create('agent2@test@example.com', 'test@example.com', 'agent', 'key2', 'agent2');

    const entities = repo.getByAccountId('test@example.com');
    expect(entities.length).toBe(2);
  });

  test('updates entity status', () => {
    const accounts = new AccountRepository(db);
    accounts.create('test@example.com', 'Test User');

    repo.create('agent@test@example.com', 'test@example.com', 'agent', 'key');

    repo.updateStatus('agent@test@example.com', 'online');

    const entity = repo.getById('agent@test@example.com');
    expect(entity!.status).toBe('online');
  });

  test('availability defaults to available and updates independently of status', () => {
    const accounts = new AccountRepository(db);
    accounts.create('test@example.com', 'Test User');

    repo.create('agent@test@example.com', 'test@example.com', 'agent', 'key');

    // Default
    const initial = repo.getById('agent@test@example.com');
    expect(initial!.availability).toBe('available');

    // Pause incoming
    repo.updateAvailability('agent@test@example.com', 'unavailable');
    const paused = repo.getById('agent@test@example.com');
    expect(paused!.availability).toBe('unavailable');
    expect(paused!.status).toBe('offline'); // connection state untouched

    // Status changes do not clobber availability
    repo.updateStatus('agent@test@example.com', 'online');
    const resumed = repo.getById('agent@test@example.com');
    expect(resumed!.status).toBe('online');
    expect(resumed!.availability).toBe('unavailable');
  });

  test('getDirectoryForAccount returns own + actively granted entities only', () => {
    const accounts = new AccountRepository(db);
    const grants = new GrantRepository(db);
    accounts.create('me@example.com', 'Me');
    accounts.create('friend@example.com', 'Friend');
    accounts.create('stranger@example.com', 'Stranger');

    // Own entities
    repo.create('mine1@me@example.com', 'me@example.com', 'agent', 'k1');
    repo.create('mine2@me@example.com', 'me@example.com', 'agent', 'k2');
    // Friend shares two entities with me
    repo.create('shared1@friend@example.com', 'friend@example.com', 'agent', 'k3');
    repo.create('shared2@friend@example.com', 'friend@example.com', 'agent', 'k4');
    // Stranger's entity — never granted
    repo.create('hidden@stranger@example.com', 'stranger@example.com', 'agent', 'k5');
    // Friend's other entity — granted, then revoked
    repo.create('revoked@friend@example.com', 'friend@example.com', 'agent', 'k6');

    const activeGrant = grants.create('friend@example.com', 'me@example.com', 'shared1@friend@example.com');
    grants.create('friend@example.com', 'me@example.com', 'shared2@friend@example.com');
    const revokedGrant = grants.create('friend@example.com', 'me@example.com', 'revoked@friend@example.com');
    grants.revoke(revokedGrant.id);

    const directory = repo.getDirectoryForAccount('me@example.com');
    const ids = directory.map(e => e.id).sort();

    // Own 2 + actively granted 2; revoked grant and stranger excluded
    expect(ids).toEqual([
      'mine1@me@example.com',
      'mine2@me@example.com',
      'shared1@friend@example.com',
      'shared2@friend@example.com',
    ]);

    // The active grant is still referenced (avoid unused-var lint noise)
    expect(activeGrant.status).toBe('active');
  });

  test('getDirectoryForAccount excludes expired grants', () => {
    const accounts = new AccountRepository(db);
    const grants = new GrantRepository(db);
    accounts.create('owner@example.com', 'Owner');
    accounts.create('grantee@example.com', 'Grantee');

    repo.create('shared@owner@example.com', 'owner@example.com', 'agent', 'k1');
    repo.create('caller@grantee@example.com', 'grantee@example.com', 'agent', 'k2');

    // Expired grant (ISO format, same-day-safe via datetime() normalization)
    grants.create(
      'owner@example.com', 'grantee@example.com', 'shared@owner@example.com', {},
      new Date(Date.now() - 60_000).toISOString()
    );

    const directory = repo.getDirectoryForAccount('grantee@example.com');
    expect(directory.map(e => e.id)).toEqual(['caller@grantee@example.com']);
  });
});

describe('ChannelRepository', () => {
  let db: Database;
  let repo: ChannelRepository;

  beforeEach(() => {
    db = new Database(':memory:');
    initializeDatabase(db);
    repo = new ChannelRepository(db);
  });

  afterEach(() => {
    db.close();
  });

  test('creates and retrieves channel', () => {
    const accounts = new AccountRepository(db);
    accounts.create('test@example.com', 'Test User');
    const entities = new EntityRepository(db);
    entities.create('agent@test@example.com', 'test@example.com', 'agent', 'key');

    const channel = repo.create('General', 'agent@test@example.com', true);

    expect(channel.id).toBeDefined();
    expect(channel.name).toBe('General');
    expect(channel.is_public).toBe(true);

    const retrieved = repo.getById(channel.id);
    expect(retrieved).toBeDefined();
    expect(retrieved!.name).toBe('General');
  });

  test('adds and removes members', () => {
    const accounts = new AccountRepository(db);
    accounts.create('test@example.com', 'Test User');
    const entities = new EntityRepository(db);
    entities.create('agent@test@example.com', 'test@example.com', 'agent', 'key');

    const channel = repo.create('General', 'agent@test@example.com', true);

    repo.addMember(channel.id, 'agent@test@example.com');

    expect(repo.isMember(channel.id, 'agent@test@example.com')).toBe(true);

    const members = repo.getMembers(channel.id);
    expect(members.length).toBe(1);
    expect(members[0].entity_id).toBe('agent@test@example.com');

    repo.removeMember(channel.id, 'agent@test@example.com');
    expect(repo.isMember(channel.id, 'agent@test@example.com')).toBe(false);
  });

  test('kick removes member but allows rejoin', () => {
    const accounts = new AccountRepository(db);
    accounts.create('test@example.com', 'Test User');
    const entities = new EntityRepository(db);
    entities.create('owner@test@example.com', 'test@example.com', 'agent', 'key1');
    entities.create('target@test@example.com', 'test@example.com', 'agent', 'key2');

    const channel = repo.create('General', 'owner@test@example.com', true);
    repo.addMember(channel.id, 'target@test@example.com');

    repo.kick(channel.id, 'target@test@example.com');
    expect(repo.isMember(channel.id, 'target@test@example.com')).toBe(false);

    // Can rejoin after kick (channel moderation is kick + set-role; blocking
    // is handled by the account permission matrix)
    repo.addMember(channel.id, 'target@test@example.com');
    expect(repo.isMember(channel.id, 'target@test@example.com')).toBe(true);
  });

  test('updates member role', () => {
    const accounts = new AccountRepository(db);
    accounts.create('test@example.com', 'Test User');
    const entities = new EntityRepository(db);
    entities.create('owner@test@example.com', 'test@example.com', 'agent', 'key1');
    entities.create('member@test@example.com', 'test@example.com', 'agent', 'key2');

    const channel = repo.create('General', 'owner@test@example.com', true);
    repo.addMember(channel.id, 'member@test@example.com');

    expect(repo.getMemberRole(channel.id, 'member@test@example.com')).toBe('member');

    repo.updateMemberRole(channel.id, 'member@test@example.com', 'admin');
    expect(repo.getMemberRole(channel.id, 'member@test@example.com')).toBe('admin');
  });
});

describe('MessageRepository', () => {
  let db: Database;
  let repo: MessageRepository;
  let entities: EntityRepository;
  let channels: ChannelRepository;

  beforeEach(() => {
    db = new Database(':memory:');
    initializeDatabase(db);
    repo = new MessageRepository(db);
    entities = new EntityRepository(db);
    channels = new ChannelRepository(db);

    // Create test accounts and entities
    const accounts = new AccountRepository(db);
    accounts.create('test.com', 'Test');
    accounts.create('other.com', 'Other');
    entities.create('sender@test.com', 'test.com', 'agent', 'key1');
    entities.create('recipient@test.com', 'test.com', 'agent', 'key2');
    entities.create('other@other.com', 'other.com', 'agent', 'key3');
  });

  afterEach(() => {
    db.close();
  });

  test('sends direct message', async () => {
    const message = await repo.sendDirectMessage(
      'sender@test.com',
      'recipient@test.com',
      'Hello, world!'
    );

    expect(message.id).toBeDefined();
    expect(message.from_entity).toBe('sender@test.com');
    expect(message.to_entity).toBe('recipient@test.com');
    expect(message.text).toBe('Hello, world!');
    // Delivery state is per recipient — ask message_deliveries, not the message.
    expect(repo.getUndeliveredCount('recipient@test.com')).toBeGreaterThan(0);
  });

  test('sends channel message', async () => {
    const channel = channels.create('general', 'sender@test.com', true);
    const message = await repo.sendChannelMessage(
      'sender@test.com',
      channel.id,
      'Hello, channel!'
    );

    expect(message.id).toBeDefined();
    expect(message.from_entity).toBe('sender@test.com');
    expect(message.channel_id).toBe(channel.id);
    expect(message.text).toBe('Hello, channel!');
  });

  test('marks messages as delivered', async () => {
    const msg1 = await repo.sendDirectMessage('sender@test.com', 'recipient@test.com', 'Message 1');
    const msg2 = await repo.sendDirectMessage('sender@test.com', 'recipient@test.com', 'Message 2');

    repo.markDelivered('recipient@test.com', [msg1.id, msg2.id]);

    // Delivery is per recipient now, so assert on what the recipient sees
    // rather than on the shared messages.delivered column.
    const undelivered = await repo.getUndelivered('recipient@test.com');
    expect(undelivered.some(m => m.id === msg1.id)).toBe(false);
    expect(undelivered.some(m => m.id === msg2.id)).toBe(false);
  });

  test('getOwnedMessageIds filters to owned messages', async () => {
    const msg1 = await repo.sendDirectMessage('sender@test.com', 'recipient@test.com', 'dm to recipient');
    const msg2 = await repo.sendDirectMessage('sender@test.com', 'other@other.com', 'dm to other');
    const channel = channels.create('owned-room', 'sender@test.com', true);
    const msg3 = await repo.sendChannelMessage('sender@test.com', channel.id, 'channel msg');

    // Ownership is now "has a delivery row", i.e. was an actual recipient.
    const owned = repo.getOwnedMessageIds('recipient@test.com', [msg1.id, msg2.id, msg3.id]);
    expect(owned).toEqual([msg1.id]);

    // The sender owns NOTHING here: msg1 and msg2 are their outgoing DMs, and
    // a sender is excluded from their own channel fan-out. Previously channel
    // membership made them "own" msg3, which meant acknowledging delivery of a
    // message they wrote.
    const senderOwned = repo.getOwnedMessageIds('sender@test.com', [msg1.id, msg2.id, msg3.id]);
    expect(senderOwned).toEqual([]);

    // A real member of the channel does own it.
    channels.addMember(channel.id, 'recipient@test.com', 'member');
    const msg4 = await repo.sendChannelMessage('sender@test.com', channel.id, 'after joining');
    expect(repo.getOwnedMessageIds('recipient@test.com', [msg4.id])).toEqual([msg4.id]);
  });

  test('gets direct message history', async () => {
    await repo.sendDirectMessage('sender@test.com', 'recipient@test.com', 'Message 1');
    await repo.sendDirectMessage('sender@test.com', 'recipient@test.com', 'Message 2');
    await repo.sendDirectMessage('sender@test.com', 'other@other.com', 'Message 3');

    const history = await repo.getDirectMessageHistory('sender@test.com', 'recipient@test.com');
    expect(history.length).toBe(2);
  });

  test('gets channel history', async () => {
    const channel = channels.create('general', 'sender@test.com', true);
    await repo.sendChannelMessage('sender@test.com', channel.id, 'Message 1');
    await repo.sendChannelMessage('sender@test.com', channel.id, 'Message 2');

    const history = await repo.getChannelHistory(channel.id);
    expect(history.length).toBe(2);
  });

  test('gets undelivered messages for entity', async () => {
    await repo.sendDirectMessage('sender@test.com', 'recipient@test.com', 'Message 1');

    const undelivered = await repo.getUndelivered('recipient@test.com');
    expect(undelivered.length).toBe(1);
    expect(undelivered[0].text).toBe('Message 1');

    // After marking delivered, no more undelivered
    repo.markDelivered('recipient@test.com', undelivered.map(m => m.id));
    const after = await repo.getUndelivered('recipient@test.com');
    expect(after.length).toBe(0);
  });
});

describe('SessionRepository', () => {
  let db: Database;
  let repo: SessionRepository;

  beforeEach(() => {
    db = new Database(':memory:');
    initializeDatabase(db);
    repo = new SessionRepository(db);
  });

  afterEach(() => {
    db.close();
  });

  test('creates and retrieves session', () => {
    // Create account and entity first (foreign key constraint)
    const accounts = new AccountRepository(db);
    accounts.create('test.com', 'Test');
    const entities = new EntityRepository(db);
    entities.create('agent@test.com', 'test.com', 'agent', 'key');

    const session = repo.create('agent@test.com');

    expect(session.id).toBeDefined();
    expect(session.entity_id).toBe('agent@test.com');

    const retrieved = repo.getById(session.id);
    expect(retrieved).toBeDefined();
    expect(retrieved!.entity_id).toBe('agent@test.com');
  });

  test('updates heartbeat', () => {
    const accounts = new AccountRepository(db);
    accounts.create('test.com', 'Test');
    const entities = new EntityRepository(db);
    entities.create('agent@test.com', 'test.com', 'agent', 'key');

    const session = repo.create('agent@test.com');
    const originalHeartbeat = new Date(session.last_heartbeat).getTime();

    repo.updateHeartbeat(session.id);

    const updated = repo.getById(session.id);
    const newHeartbeat = new Date(updated!.last_heartbeat).getTime();
    expect(newHeartbeat).toBeGreaterThanOrEqual(originalHeartbeat);
  });

  test('deletes session', () => {
    const accounts = new AccountRepository(db);
    accounts.create('test.com', 'Test');
    const entities = new EntityRepository(db);
    entities.create('agent@test.com', 'test.com', 'agent', 'key');

    const session = repo.create('agent@test.com');
    repo.delete(session.id);

    const retrieved = repo.getById(session.id);
    expect(retrieved).toBeNull();
  });
});

describe('InvitationRepository', () => {
  let db: Database;
  let repo: InvitationRepository;
  let channels: ChannelRepository;
  let entities: EntityRepository;

  beforeEach(() => {
    db = new Database(':memory:');
    initializeDatabase(db);
    repo = new InvitationRepository(db);
    channels = new ChannelRepository(db);
    entities = new EntityRepository(db);

    // Create test accounts and entities
    const accounts = new AccountRepository(db);
    accounts.create('test.com', 'Test');
    entities.create('admin@test.com', 'test.com', 'agent', 'key1');
    entities.create('user@test.com', 'test.com', 'agent', 'key2');
  });

  afterEach(() => {
    db.close();
  });

  test('creates and retrieves invitation', () => {
    const channel = channels.create('general', 'admin@test.com', false);
    const invitation = repo.create(channel.id, 'admin@test.com', 'user@test.com');

    expect(invitation.id).toBeDefined();
    expect(invitation.channel_id).toBe(channel.id);
    expect(invitation.invited_by).toBe('admin@test.com');
    expect(invitation.invited_entity).toBe('user@test.com');
    expect(invitation.status).toBe('pending');

    const retrieved = repo.getById(invitation.id);
    expect(retrieved).toBeDefined();
    expect(retrieved!.status).toBe('pending');
  });

  test('accepts invitation', () => {
    const channel = channels.create('general', 'admin@test.com', false);
    const invitation = repo.create(channel.id, 'admin@test.com', 'user@test.com');

    repo.accept(invitation.id);

    const retrieved = repo.getById(invitation.id);
    expect(retrieved!.status).toBe('accepted');
  });

  test('declines invitation', () => {
    const channel = channels.create('general', 'admin@test.com', false);
    const invitation = repo.create(channel.id, 'admin@test.com', 'user@test.com');

    repo.decline(invitation.id);

    const retrieved = repo.getById(invitation.id);
    expect(retrieved!.status).toBe('declined');
  });

  test('lists pending invitations for entity', () => {
    const channel1 = channels.create('general', 'admin@test.com', false);
    const channel2 = channels.create('random', 'admin@test.com', false);

    repo.create(channel1.id, 'admin@test.com', 'user@test.com');
    repo.create(channel2.id, 'admin@test.com', 'user@test.com');

    const pending = repo.getPendingForEntity('user@test.com');
    expect(pending.length).toBe(2);
  });
});

describe('GrantRepository', () => {
  let db: Database;
  let repo: GrantRepository;
  let entities: EntityRepository;

  const GRANTOR = 'grantor.example.com';
  const GRANTEE = 'grantee.example.com';

  beforeEach(() => {
    db = new Database(':memory:');
    initializeDatabase(db);
    repo = new GrantRepository(db);
    entities = new EntityRepository(db);

    const accounts = new AccountRepository(db);
    accounts.create(GRANTOR, 'Grantor');
    accounts.create(GRANTEE, 'Grantee');
    entities.create('shared@grantor.example.com', GRANTOR, 'agent', 'key1');
    entities.create('caller@grantee.example.com', GRANTEE, 'agent', 'key2');
  });

  afterEach(() => {
    db.close();
  });

  test('creates and finds an active grant', () => {
    const grant = repo.create(GRANTOR, GRANTEE, 'shared@grantor.example.com');
    expect(grant.status).toBe('active');
    expect(grant.capabilities).toEqual({});

    const found = repo.findActive(GRANTOR, GRANTEE, 'shared@grantor.example.com');
    expect(found).not.toBeNull();
    expect(found!.id).toBe(grant.id);
  });

  test('revoked grant is not active', () => {
    const grant = repo.create(GRANTOR, GRANTEE, 'shared@grantor.example.com');
    expect(repo.revoke(grant.id)).toBe(true);
    expect(repo.findActive(GRANTOR, GRANTEE, 'shared@grantor.example.com')).toBeNull();

    // Revocation is idempotent
    expect(repo.revoke(grant.id)).toBe(false);
  });

  test('expired grant is not active and cleanup revokes it', () => {
    const pastDate = new Date(Date.now() - 60_000).toISOString().replace('T', ' ').slice(0, 19);
    repo.create(GRANTOR, GRANTEE, 'shared@grantor.example.com', {}, pastDate);

    expect(repo.findActive(GRANTOR, GRANTEE, 'shared@grantor.example.com')).toBeNull();

    const revoked = repo.revokeExpired();
    expect(revoked).toBe(1);
  });

  test('ISO-8601 expires_at (with T/Z) is compared correctly', () => {
    // ISO format from JS Date.toISOString() — same-day expiry must register
    const expired = repo.create(
      GRANTOR, GRANTEE, 'shared@grantor.example.com', {},
      new Date(Date.now() - 3_600_000).toISOString() // 1h ago, same UTC day possible
    );
    expect(repo.findActive(GRANTOR, GRANTEE, 'shared@grantor.example.com')).toBeNull();

    // Future ISO date is active (second entity — tuple UNIQUE constraint)
    entities.create('shared2@grantor.example.com', GRANTOR, 'agent', 'key3');
    repo.create(
      GRANTOR, GRANTEE, 'shared2@grantor.example.com', {},
      new Date(Date.now() + 3_600_000).toISOString()
    );
    expect(repo.findActive(GRANTOR, GRANTEE, 'shared2@grantor.example.com')).not.toBeNull();

    expect(expired.status).toBe('active'); // row still exists, just expired
  });

  test('stores capabilities JSON', () => {
    repo.create(GRANTOR, GRANTEE, 'shared@grantor.example.com', { can_send: false });
    const found = repo.findActive(GRANTOR, GRANTEE, 'shared@grantor.example.com');
    expect(found!.capabilities).toEqual({ can_send: false });
  });

  test('lists by grantor and grantee', () => {
    repo.create(GRANTOR, GRANTEE, 'shared@grantor.example.com');
    expect(repo.listByGrantor(GRANTOR).length).toBe(1);
    expect(repo.listByGrantee(GRANTEE).length).toBe(1);
    expect(repo.listByGrantor(GRANTEE).length).toBe(0);
  });
});

describe('PermissionRepository', () => {
  let db: Database;
  let repo: PermissionRepository;
  let entities: EntityRepository;

  const OWNER = 'owner.example.com';
  const OTHER = 'other.example.com';

  beforeEach(() => {
    db = new Database(':memory:');
    initializeDatabase(db);
    repo = new PermissionRepository(db);
    entities = new EntityRepository(db);

    const accounts = new AccountRepository(db);
    accounts.create(OWNER, 'Owner');
    accounts.create(OTHER, 'Other');
    entities.create('protected@owner.example.com', OWNER, 'agent', 'key1');
    entities.create('noisy@other.example.com', OTHER, 'agent', 'key2');
  });

  afterEach(() => {
    db.close();
  });

  test('creates and lists rules', () => {
    const rule = repo.create({
      account_id: OWNER,
      target_type: 'entity',
      target_entity_id: 'protected@owner.example.com',
      source_type: 'entity',
      source_entity_id: 'noisy@other.example.com',
      action: 'deny',
    });

    expect(rule.id).toBeDefined();
    expect(rule.action).toBe('deny');

    const rules = repo.listByAccount(OWNER);
    expect(rules.length).toBe(1);
    expect(rules[0].target_entity_id).toBe('protected@owner.example.com');
  });

  test('rejects identical duplicate rules', () => {
    const base = {
      account_id: OWNER,
      target_type: 'entity' as const,
      target_entity_id: 'protected@owner.example.com',
      source_type: 'entity' as const,
      source_entity_id: 'noisy@other.example.com',
      action: 'deny' as const,
    };
    repo.create(base);
    expect(() => repo.create(base)).toThrow('conflict');

    // Same tuple but opposite action is also a conflict (ambiguous resolution)
    expect(() => repo.create({ ...base, action: 'allow' })).toThrow('conflict');
  });

  test('account-wide deny-all rule', () => {
    repo.create({
      account_id: OWNER,
      target_type: 'all',
      source_type: 'account',
      source_account_id: OTHER,
      action: 'deny',
    });
    const rules = repo.listByAccount(OWNER);
    expect(rules[0].target_type).toBe('all');
    expect(rules[0].source_account_id).toBe(OTHER);
  });

  test('deleteForAccount enforces ownership', () => {
    const rule = repo.create({
      account_id: OWNER,
      target_type: 'all',
      source_type: 'account',
      source_account_id: OTHER,
      action: 'deny',
    });

    // Wrong account cannot delete
    expect(repo.deleteForAccount(rule.id, OTHER)).toBe(false);
    // Owner can
    expect(repo.deleteForAccount(rule.id, OWNER)).toBe(true);
    expect(repo.listByAccount(OWNER).length).toBe(0);
  });
});
