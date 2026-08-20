import { test, expect, describe, beforeAll, afterAll } from 'bun:test';
import { startServer, stopServer } from '../http';
import { getDatabaseContext, closeDatabase } from '../../db';
import { generateKeyPair, bufferToBase64, sign, base64ToBuffer } from '../../crypto/keys';
import { decryptPrivateKey } from '../../crypto/encrypt';
import { hashToken } from '../../auth/oauth';

// ============================================================================
// Test Configuration
// ============================================================================

const TEST_PORT = 17899;
const TEST_HOST = '127.0.0.1';
const TEST_SERVER_URL = `http://${TEST_HOST}:${TEST_PORT}`;
const TEST_SECRET = process.env.FAM_SERVER_SECRET!;

process.env.FAM_PORT = String(TEST_PORT);
process.env.FAM_HOST = TEST_HOST;

// ============================================================================
// Helpers
// ============================================================================

async function seedAccount(accountId: string, token: string): Promise<void> {
  const ctx = getDatabaseContext();
  ctx.db.prepare(`INSERT OR IGNORE INTO accounts (id) VALUES (?)`).run(accountId);
  const tokenHash = await hashToken(token, TEST_SECRET);
  const authId = `auth-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  ctx.db.prepare(`
    INSERT OR IGNORE INTO authorizations (id, account_id, server_id, token_hash)
    VALUES (?, ?, 'local', ?)
  `).run(authId, accountId, tokenHash);
}

/**
 * Seed an active cross-account grant: grantor shares entityId with grantee.
 */
async function seedGrant(grantor: string, grantee: string, entityId: string): Promise<void> {
  const ctx = getDatabaseContext();
  ctx.grants.create(grantor, grantee, entityId);
}

/**
 * Create a fresh session for an entity (fast path for session-authenticated
 * route tests — skips the Argon2 challenge dance).
 */
async function seedSession(entityId: string): Promise<string> {
  const ctx = getDatabaseContext();
  const session = ctx.sessions.create(entityId);
  return session.id;
}

async function createEntity(
  accountToken: string,
  name: string,
  passkey = 'test-passkey',
  capabilities?: Record<string, boolean>
): Promise<{ entity_id: string; public_key: string; encrypted_key_file: any }> {
  const body: any = { account_token: accountToken, name, type: 'agent', passkey };
  if (capabilities) body.capabilities = capabilities;

  const res = await fetch(`${TEST_SERVER_URL}/accounts/create-entity`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await res.json() as any;
  expect(res.status).toBe(201);
  return { entity_id: data.entity_id, public_key: data.public_key, encrypted_key_file: data.encrypted_key_file };
}

async function authenticateEntity(
  entityId: string,
  publicKey: string,
  passkey: string,
  encryptedKeyFile: any
): Promise<string> {
  const authData = await authenticateEntityFull(entityId, publicKey, passkey, encryptedKeyFile);
  return authData.session_id;
}

/**
 * Full entity auth flow (connect → decrypt → sign → authenticate).
 * Returns the complete authenticate response.
 */
async function authenticateEntityFull(
  entityId: string,
  publicKey: string,
  passkey: string,
  encryptedKeyFile: any
): Promise<any> {
  // Connect
  const { status: cs, data: connectData } = await api('/entities/connect', {
    entity_id: entityId,
    public_key: publicKey,
  });
  expect(cs).toBe(200);

  // Decrypt private key
  const privateKeyBase64 = await decryptPrivateKey(encryptedKeyFile, passkey);

  // Sign nonce (base64-decoded, matching the server's verification)
  const nonceBytes = base64ToBuffer(connectData.nonce);
  const signature = await sign(nonceBytes, privateKeyBase64);

  // Authenticate
  const { status: as, data: authData } = await api('/entities/authenticate', {
    entity_id: entityId,
    nonce: connectData.nonce,
    signature,
  });
  expect(as).toBe(200);

  return authData;
}

/**
 * Send exactly the given body — no session injected. Use this when the test is
 * ABOUT authentication.
 */
async function rawApi(path: string, body: object): Promise<{ status: number; data: any }> {
  const res = await fetch(`${TEST_SERVER_URL}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, data: await res.json() as any };
}

// Entity-scoped routes derive identity from an authenticated session. Tests
// that are not about auth shouldn't each re-run the challenge-response dance,
// so attach a cached session for whichever entity the body names.
const sessionCache = new Map<string, string>();

async function sessionFor(entityId: string): Promise<string> {
  let existing = sessionCache.get(entityId);
  if (!existing) {
    existing = await seedSession(entityId);
    sessionCache.set(entityId, existing);
  }
  return existing;
}

// These establish a session rather than consuming one.
const NO_SESSION_ROUTES = new Set(['/entities/connect', '/entities/authenticate']);

async function api(path: string, body: any): Promise<{ status: number; data: any }> {
  const payload = { ...body };
  if (payload.entity_id && !payload.session_id && !NO_SESSION_ROUTES.has(path)) {
    payload.session_id = await sessionFor(payload.entity_id);
  }
  return rawApi(path, payload);
}

// ============================================================================
// Tests
// ============================================================================

describe('FAM Server Integration', () => {
  const testAccountId = 'integration@example.com';
  const testToken = 'test-integration-token';

  beforeAll(async () => {
    await seedAccount(testAccountId, testToken);
    startServer({ port: TEST_PORT, host: TEST_HOST });
    await Bun.sleep(500);
  });

  afterAll(() => {
    stopServer();
    closeDatabase();
  });

  // -- Health ---------------------------------------------------------------

  test('GET /health returns ok', async () => {
    const res = await fetch(`${TEST_SERVER_URL}/health`);
    expect(res.status).toBe(200);
    const data = await res.json() as any;
    expect(data.status).toBe('ok');
    expect(data.entities).toBeDefined();
  });

  test('GET / returns version', async () => {
    const res = await fetch(`${TEST_SERVER_URL}/`);
    expect(res.status).toBe(200);
    const data = await res.json() as any;
    expect(data.version).toBe('0.1.0');
  });

  // -- Entity Creation ------------------------------------------------------

  test('create-entity with valid token and passkey', async () => {
    const { status, data } = await api('/accounts/create-entity', {
      account_token: testToken,
      name: 'test-agent',
      type: 'agent',
      passkey: 'my-passkey',
    });

    expect(status).toBe(201);
    expect(data.entity_id).toBe('test-agent@integration@example.com');
    expect(data.public_key).toBeDefined();
    expect(data.encrypted_key_file).toBeDefined();
    expect(data.encrypted_key_file.kdf).toBe('argon2id');
  });

  test('create-entity fails without passkey', async () => {
    const { status, data } = await api('/accounts/create-entity', {
      account_token: testToken,
      name: 'no-pass',
      type: 'agent',
    });

    expect(status).toBe(400);
    expect(data.error).toContain('Passkey is required');
  });

  test('create-entity fails with bad token', async () => {
    const { status } = await api('/accounts/create-entity', {
      account_token: 'bad-token',
      name: 'bad-entity',
      type: 'agent',
      passkey: 'pass',
    });
    expect(status).toBe(401);
  });

  test('create-entity fails with duplicate name', async () => {
    const { status, data } = await api('/accounts/create-entity', {
      account_token: testToken,
      name: 'test-agent',
      type: 'agent',
      passkey: 'pass',
    });
    expect(status).toBe(409);
  });

  test('list-entities returns created entities', async () => {
    const { status, data } = await api('/accounts/list-entities', {
      account_token: testToken,
    });
    expect(status).toBe(200);
    expect(data.entities.length).toBeGreaterThanOrEqual(1);
  });

  // -- Entity Auth Flow -----------------------------------------------------

  test('connect returns nonce challenge', async () => {
    const { entity_id, public_key } = await createEntity(testToken, 'connect-agent');

    const { status, data } = await api('/entities/connect', {
      entity_id,
      public_key,
    });

    expect(status).toBe(200);
    expect(data.nonce).toBeDefined();
    expect(data.nonce.length).toBeGreaterThan(0);
  });

  test('connect fails for nonexistent entity', async () => {
    const keyPair = await generateKeyPair();
    const publicKey = bufferToBase64(keyPair.publicKey);

    const { status } = await api('/entities/connect', {
      entity_id: 'ghost@nobody.com',
      public_key: publicKey,
    });
    expect(status).toBe(404);
  });

  test('full auth flow: connect + decrypt + sign + authenticate', async () => {
    const passkey = 'auth-passkey';
    const { entity_id, public_key, encrypted_key_file } = await createEntity(
      testToken, 'auth-agent', passkey
    );

    const sessionId = await authenticateEntity(entity_id, public_key, passkey, encrypted_key_file);
    expect(sessionId).toBeDefined();
    expect(typeof sessionId).toBe('string');
    expect(sessionId.length).toBeGreaterThan(0);
  });

  // -- Channels -------------------------------------------------------------

  test('create, list, and join channel', async () => {
    const { entity_id: creator } = await createEntity(
      testToken, 'chan-creator', 'cpk',
      { can_create_channels: true, can_send: true }
    );

    const { status: cs, data: cd } = await api('/channels/create', {
      entity_id: creator, name: 'test-room', is_public: true,
    });
    expect(cs).toBe(201);
    expect(cd.channel.name).toBe('test-room');

    const { status: ls, data: ld } = await api('/channels/list', {
      entity_id: creator,
    });
    expect(ls).toBe(200);
    expect(ld.channels.length).toBeGreaterThanOrEqual(1);
    expect(ld.total).toBeDefined();
    expect(ld.limit).toBeDefined();

    const { entity_id: joiner } = await createEntity(
      testToken, 'chan-joiner', 'jk', { can_send: true }
    );

    const { status: js } = await api('/channels/join', {
      entity_id: joiner, channel_id: cd.channel.id,
    });
    expect(js).toBe(200);

    const { status: ms, data: md } = await api('/channels/list-members', {
      entity_id: creator, channel_id: cd.channel.id,
    });
    expect(ms).toBe(200);
    expect(md.members.length).toBeGreaterThanOrEqual(2);
  });

  // -- Messages -------------------------------------------------------------

  test('cross-account DM is default-deny without a grant', async () => {
    const sToken = 's2-token';
    const rToken = 'r2-token';
    await seedAccount('sender2@msg.example.com', sToken);
    await seedAccount('receiver2@msg.example.com', rToken);

    const { entity_id: s } = await createEntity(sToken, 'sender2');
    const { entity_id: r } = await createEntity(rToken, 'receiver2');

    const { status } = await api('/messages/send', {
      entity_id: s, to_entity: r, text: 'should be denied',
    });
    expect(status).toBe(403);
  });

  test('send direct message with an active grant', async () => {
    const sToken = 's-token';
    const rToken = 'r-token';
    await seedAccount('sender@msg.example.com', sToken);
    await seedAccount('receiver@msg.example.com', rToken);

    const { entity_id: s } = await createEntity(sToken, 'sender');
    const { entity_id: r } = await createEntity(rToken, 'receiver');

    // Receiver's account grants the sender's account access to the receiver entity
    await seedGrant('receiver@msg.example.com', 'sender@msg.example.com', r);

    const { status, data } = await api('/messages/send', {
      entity_id: s, to_entity: r, text: 'Hello integration!',
    });
    expect(status).toBe(201);
    expect(data.message_id).toBeGreaterThan(0);
  });

  test('deny rule overrides an active grant', async () => {
    const sToken = 's3-token';
    const rToken = 'r3-token';
    const sAccount = 'sender3@msg.example.com';
    const rAccount = 'receiver3@msg.example.com';
    await seedAccount(sAccount, sToken);
    await seedAccount(rAccount, rToken);

    const { entity_id: s } = await createEntity(sToken, 'sender3');
    const { entity_id: r } = await createEntity(rToken, 'receiver3');

    await seedGrant(rAccount, sAccount, r);

    // Receiver's account adds a deny rule for the whole sender account
    const ctx = getDatabaseContext();
    ctx.permissions.create({
      account_id: rAccount,
      target_type: 'all',
      source_type: 'account',
      source_account_id: sAccount,
      action: 'deny',
    });

    const { status } = await api('/messages/send', {
      entity_id: s, to_entity: r, text: 'denied by rule',
    });
    expect(status).toBe(403);
  });

  test('same-account DM is default-allow', async () => {
    const token = 'sa-token';
    await seedAccount('sameacct@example.com', token);

    const { entity_id: a } = await createEntity(token, 'same-a');
    const { entity_id: b } = await createEntity(token, 'same-b');

    const { status, data } = await api('/messages/send', {
      entity_id: a, to_entity: b, text: 'internal hello',
    });
    expect(status).toBe(201);
    expect(data.message_id).toBeGreaterThan(0);
  });

  test('message history returns messages with pagination metadata', async () => {
    const sToken = 'hs-token';
    const rToken = 'hr-token';
    const sAccount = 'hsender@hist.example.com';
    const rAccount = 'hreceiver@hist.example.com';
    await seedAccount(sAccount, sToken);
    await seedAccount(rAccount, rToken);

    const { entity_id: s } = await createEntity(sToken, 'hs');
    const { entity_id: r } = await createEntity(rToken, 'hr');

    await seedGrant(rAccount, sAccount, r);
    await seedGrant(sAccount, rAccount, s);

    await api('/messages/send', { entity_id: s, to_entity: r, text: 'msg-1' });
    await api('/messages/send', { entity_id: r, to_entity: s, text: 'msg-2' });

    const { status, data } = await api('/messages/history', {
      entity_id: s, other_entity_id: r,
    });
    expect(status).toBe(200);
    expect(data.messages.length).toBe(2);
    expect(data.limit).toBeDefined();
    expect(data.offset).toBeDefined();
  });

  test('send channel message', async () => {
    const token = 'ct-token';
    await seedAccount('csender@chan.example.com', token);

    const { entity_id: sender } = await createEntity(
      token, 'cs', 'cs-pk',
      { can_create_channels: true, can_send: true }
    );

    const { data: ch } = await api('/channels/create', {
      entity_id: sender, name: 'msg-room', is_public: true,
    });

    const { entity_id: receiver } = await createEntity(
      token, 'cr', 'cr-pk', { can_send: true }
    );
    await api('/channels/join', { entity_id: receiver, channel_id: ch.channel.id });

    const { status, data } = await api('/messages/send', {
      entity_id: sender, channel_id: ch.channel.id, text: 'Hello channel!',
    });
    expect(status).toBe(201);
    expect(data.message_id).toBeDefined();
  });

  // -- Admin Channel Operations ----------------------------------------------

  test('channel admin: kick and set-role with permission checks', async () => {
    const token = 'admin-token';
    await seedAccount('admin@chan.example.com', token);

    const { entity_id: owner } = await createEntity(
      token, 'adm-owner', 'ao-pk', { can_create_channels: true, can_send: true }
    );
    const { entity_id: member } = await createEntity(
      token, 'adm-member', 'am-pk', { can_send: true }
    );
    const { entity_id: outsider } = await createEntity(
      token, 'adm-outsider', 'ax-pk', { can_send: true }
    );

    const { data: ch } = await api('/channels/create', {
      entity_id: owner, name: 'admin-room', is_public: true,
    });
    const channelId = ch.channel.id;

    await api('/channels/join', { entity_id: member, channel_id: channelId });

    // Outsider (not a member) cannot kick
    const { status: outsiderKick } = await api('/channels/kick', {
      entity_id: outsider, channel_id: channelId, target_entity: member,
    });
    expect(outsiderKick).toBe(403);

    // Owner kicks member
    const { status: kickStatus } = await api('/channels/kick', {
      entity_id: owner, channel_id: channelId, target_entity: member,
    });
    expect(kickStatus).toBe(200);

    // Kicked member can rejoin (public channel; channel moderation is kick +
    // set-role — cross-account blocking uses the permission matrix)
    const { status: rejoinStatus } = await api('/channels/join', {
      entity_id: member, channel_id: channelId,
    });
    expect(rejoinStatus).toBe(200);

    // Set role: only owner can
    const { status: memberSetRole } = await api('/channels/set-role', {
      entity_id: member, channel_id: channelId, target_entity: member, role: 'admin',
    });
    expect(memberSetRole).toBe(403);

    const { status: ownerSetRole } = await api('/channels/set-role', {
      entity_id: owner, channel_id: channelId, target_entity: member, role: 'admin',
    });
    expect(ownerSetRole).toBe(200);

    // Verify role change
    const { data: membersData } = await api('/channels/list-members', {
      entity_id: owner, channel_id: channelId,
    });
    const memberEntry = membersData.members.find((m: any) => m.entity_id === member);
    expect(memberEntry.role).toBe('admin');

    // Cannot kick the owner
    const { status: kickOwner } = await api('/channels/kick', {
      entity_id: owner, channel_id: channelId, target_entity: owner,
    });
    expect(kickOwner).toBe(403);

    // Retired ban routes are gone (404)
    const { status: banGone } = await api('/channels/ban', {
      entity_id: owner, channel_id: channelId, target_entity: member,
    });
    expect(banGone).toBe(404);
  });

  // -- Admin API: Grants & Permissions ----------------------------------------

  test('admin API: grant lifecycle (create, list, revoke) with ownership checks', async () => {
    const ownerToken = 'grant-owner-token';
    const otherToken = 'grant-other-token';
    const ownerAccount = 'grantowner@example.com';
    const otherAccount = 'grantother@example.com';
    await seedAccount(ownerAccount, ownerToken);
    await seedAccount(otherAccount, otherToken);

    const { entity_id: shared } = await createEntity(ownerToken, 'shared-peer');

    // Create grant: owner shares `shared` with otherAccount
    const { status: cs, data: cd } = await api('/admin/api/grants', {
      account_token: ownerToken,
      grantee_account_id: otherAccount,
      entity_id: shared,
    });
    expect(cs).toBe(201);
    expect(cd.grant.status).toBe('active');

    // Duplicate grant is a conflict
    const { status: dup } = await api('/admin/api/grants', {
      account_token: ownerToken,
      grantee_account_id: otherAccount,
      entity_id: shared,
    });
    expect(dup).toBe(409);

    // Cannot grant an entity you don't own
    const { entity_id: otherEntity } = await createEntity(otherToken, 'other-peer');
    const { status: notMine } = await api('/admin/api/grants', {
      account_token: otherToken,
      grantee_account_id: ownerAccount,
      entity_id: shared,
    });
    expect(notMine).toBe(403);

    // List grants given
    const { status: ls, data: ld } = await api('/admin/api/grants/list', {
      account_token: ownerToken, direction: 'given',
    });
    expect(ls).toBe(200);
    expect(ld.grants.length).toBe(1);
    expect(ld.grants[0].entity_id).toBe(shared);

    // List grants received (other account)
    const { status: lr, data: lrd } = await api('/admin/api/grants/list', {
      account_token: otherToken, direction: 'received',
    });
    expect(lr).toBe(200);
    expect(lrd.grants.length).toBe(1);

    // Grantee cannot revoke the grant
    const { status: wrongRevoke } = await api('/admin/api/grants/revoke', {
      account_token: otherToken, grant_id: cd.grant.id,
    });
    expect(wrongRevoke).toBe(403);

    // Grantor revokes
    const { status: rs } = await api('/admin/api/grants/revoke', {
      account_token: ownerToken, grant_id: cd.grant.id,
    });
    expect(rs).toBe(200);

    // Revoked grant no longer authorizes DMs
    const { entity_id: caller } = await createEntity(otherToken, 'grant-caller');
    const { status: dm } = await api('/messages/send', {
      entity_id: caller, to_entity: shared, text: 'should now be denied',
    });
    expect(dm).toBe(403);

    // otherEntity referenced to avoid unused warning in type space
    expect(otherEntity).toBeDefined();
  });

  test('admin API: grant then DM round-trip over HTTP', async () => {
    const ownerToken = 'gt-token';
    const callerToken = 'gc-token';
    const ownerAccount = 'gt@example.com';
    const callerAccount = 'gc@example.com';
    await seedAccount(ownerAccount, ownerToken);
    await seedAccount(callerAccount, callerToken);

    const { entity_id: shared } = await createEntity(ownerToken, 'gt-shared');
    const { entity_id: caller } = await createEntity(callerToken, 'gt-caller');

    // Denied before the grant
    const { status: before } = await api('/messages/send', {
      entity_id: caller, to_entity: shared, text: 'nope',
    });
    expect(before).toBe(403);

    // Grant via the admin API
    const { status: gs } = await api('/admin/api/grants', {
      account_token: ownerToken,
      grantee_account_id: callerAccount,
      entity_id: shared,
    });
    expect(gs).toBe(201);

    // Allowed after the grant
    const { status: after } = await api('/messages/send', {
      entity_id: caller, to_entity: shared, text: 'now yes',
    });
    expect(after).toBe(201);
  });

  test('admin API: permission rules (create, list, delete) with validation', async () => {
    const token = 'perm-token';
    const account = 'permowner@example.com';
    const otherAccount = 'permother@example.com';
    await seedAccount(account, token);
    await seedAccount(otherAccount, 'perm-other-token');

    const { entity_id: protectedEntity } = await createEntity(token, 'perm-protected');

    // Deny everything from otherAccount to a specific entity of mine
    const { status: cs, data: cd } = await api('/admin/api/permissions', {
      account_token: token,
      target_type: 'entity',
      target_entity_id: protectedEntity,
      source_type: 'account',
      source_account_id: otherAccount,
      action: 'deny',
    });
    expect(cs).toBe(201);
    expect(cd.rule.action).toBe('deny');

    // Duplicate rule → 409
    const { status: dup } = await api('/admin/api/permissions', {
      account_token: token,
      target_type: 'entity',
      target_entity_id: protectedEntity,
      source_type: 'account',
      source_account_id: otherAccount,
      action: 'deny',
    });
    expect(dup).toBe(409);

    // Invalid: entity target without target_entity_id
    const { status: noTarget } = await api('/admin/api/permissions', {
      account_token: token,
      target_type: 'entity',
      source_type: 'account',
      source_account_id: otherAccount,
      action: 'deny',
    });
    expect(noTarget).toBe(400);

    // Invalid: target entity belonging to another account
    const { entity_id: foreignEntity } = await createEntity('perm-other-token', 'perm-foreign');
    const { status: foreignTarget } = await api('/admin/api/permissions', {
      account_token: token,
      target_type: 'entity',
      target_entity_id: foreignEntity,
      source_type: 'account',
      source_account_id: otherAccount,
      action: 'deny',
    });
    expect(foreignTarget).toBe(403);

    // List
    const { status: ls, data: ld } = await api('/admin/api/permissions/list', {
      account_token: token,
    });
    expect(ls).toBe(200);
    expect(ld.rules.length).toBe(1);

    // Delete with wrong token → 404 (not owned)
    const { status: wrongDelete } = await api('/admin/api/permissions/delete', {
      account_token: 'perm-other-token', permission_id: cd.rule.id,
    });
    expect(wrongDelete).toBe(404);

    // Delete with owner token
    const { status: ds } = await api('/admin/api/permissions/delete', {
      account_token: token, permission_id: cd.rule.id,
    });
    expect(ds).toBe(200);
  });

  // -- Availability -----------------------------------------------------------

  test('availability route requires a valid session', async () => {
    const token = 'av-token';
    await seedAccount('av@example.com', token);

    const { entity_id } = await createEntity(token, 'av-peer');

    // Missing session_id
    const { status: missing } = await rawApi('/entities/availability', {
      entity_id, availability: 'unavailable',
    });
    expect(missing).toBe(400);

    // Bogus session
    const { status: bogus } = await rawApi('/entities/availability', {
      entity_id, session_id: 'not-a-session', availability: 'unavailable',
    });
    expect(bogus).toBe(404);

    // Invalid value
    const sessionId = await seedSession(entity_id);
    const { status: invalid } = await api('/entities/availability', {
      entity_id, session_id: sessionId, availability: 'busy',
    });
    expect(invalid).toBe(400);

    // Valid session works
    const { status: ok, data } = await api('/entities/availability', {
      entity_id, session_id: sessionId, availability: 'unavailable',
    });
    expect(ok).toBe(200);
    expect(data.availability).toBe('unavailable');
    expect(data.messages_pushed).toBe(0); // no WS connection → nothing pushed
  });

  test('unavailable entity: messages queue and return as undelivered at next auth', async () => {
    const token = 'avq-token';
    await seedAccount('avq@example.com', token);

    const { entity_id: recipient } = await createEntity(token, 'avq-recipient');
    const { entity_id: sender } = await createEntity(token, 'avq-sender');

    const sessionId = await seedSession(recipient);

    // Pause incoming
    const { status: pauseStatus } = await api('/entities/availability', {
      entity_id: recipient, session_id: sessionId, availability: 'unavailable',
    });
    expect(pauseStatus).toBe(200);

    // Message to the paused recipient still persists (same account: allowed)
    const { status: sendStatus, data: sendData } = await api('/messages/send', {
      entity_id: sender, to_entity: recipient, text: 'queued while away',
    });
    expect(sendStatus).toBe(201);
    expect(sendData.message_id).toBeGreaterThan(0);

    // entities/list exposes availability (default scope: all entities)
    const { data: listData } = await api('/entities/list', { entity_id: sender });
    const entry = listData.entities.find((e: any) => e.id === recipient);
    expect(entry.availability).toBe('unavailable');

    // Resume: no WS connection → backlog not pushed, but still queued
    const { data: resumeData } = await api('/entities/availability', {
      entity_id: recipient, session_id: sessionId, availability: 'available',
    });
    expect(resumeData.availability).toBe('available');
    expect(resumeData.messages_pushed).toBe(0);

    // Backlog returns at next authenticate (at-least-once; delivered stays 0
    // until the client acks)
    const ctx = getDatabaseContext();
    const undelivered = await ctx.messages.getUndelivered(recipient);
    expect(undelivered.length).toBe(1);
    expect(undelivered[0].text).toBe('queued while away');
    expect(undelivered[0].delivered).toBe(0);
  });

  test('authenticate response includes availability', async () => {
    const token = 'ava-token';
    await seedAccount('ava@example.com', token);

    const { entity_id, public_key, encrypted_key_file } = await createEntity(token, 'ava-peer');

    const sessionId = await seedSession(entity_id);
    await api('/entities/availability', {
      entity_id, session_id: sessionId, availability: 'unavailable',
    });

    const response = await authenticateEntityFull(entity_id, public_key, 'test-passkey', encrypted_key_file);
    expect(response.availability).toBe('unavailable');
  });

  // -- Directory Scoping --------------------------------------------------------

  test('entities/list scope=directory returns own + granted entities only', async () => {
    const myToken = 'dir-me-token';
    const friendToken = 'dir-friend-token';
    const strangerToken = 'dir-stranger-token';
    const myAccount = 'dirme@example.com';
    const friendAccount = 'dirfriend@example.com';
    const strangerAccount = 'dirstranger@example.com';
    await seedAccount(myAccount, myToken);
    await seedAccount(friendAccount, friendToken);
    await seedAccount(strangerAccount, strangerToken);

    const { entity_id: caller } = await createEntity(myToken, 'dir-caller');
    const { entity_id: otherMine } = await createEntity(myToken, 'dir-other-mine');
    const { entity_id: shared } = await createEntity(friendToken, 'dir-shared');
    const { entity_id: sharedRevoked } = await createEntity(friendToken, 'dir-shared-revoked');
    const { entity_id: hidden } = await createEntity(strangerToken, 'dir-hidden');

    // Friend grants access to `shared` only
    const { status: gs, data: gd } = await api('/admin/api/grants', {
      account_token: friendToken,
      grantee_account_id: myAccount,
      entity_id: shared,
    });
    expect(gs).toBe(201);

    // Grant then revoke `sharedRevoked`
    const { data: revokedGrant } = await api('/admin/api/grants', {
      account_token: friendToken,
      grantee_account_id: myAccount,
      entity_id: sharedRevoked,
    });
    await api('/admin/api/grants/revoke', {
      account_token: friendToken, grant_id: revokedGrant.grant.id,
    });

    const { status, data } = await api('/entities/list', {
      entity_id: caller, scope: 'directory',
    });
    expect(status).toBe(200);

    const ids = data.entities.map((e: any) => e.id);
    expect(ids).toContain(caller);
    expect(ids).toContain(otherMine);
    expect(ids).toContain(shared);
    expect(ids).not.toContain(sharedRevoked);
    expect(ids).not.toContain(hidden);
    expect(data.total).toBe(3);

    // Grant id referenced to keep it meaningful
    expect(gd.grant.status).toBe('active');
  });

  test('entities/list scope=directory resolves the caller from the session, not the body', async () => {
    const token = 'dir-caller-token';
    await seedAccount('dircaller@example.com', token);
    const { entity_id } = await createEntity(token, 'dir-caller');
    const sessionId = await seedSession(entity_id);

    // No session at all: rejected before any scoping happens.
    const { status: anon } = await rawApi('/entities/list', { scope: 'directory' });
    expect(anon).toBe(401);

    // Naming somebody else's entity no longer selects their directory � the
    // session owns the identity and a mismatched body assertion is refused.
    const { status: impersonated } = await rawApi('/entities/list', {
      entity_id: 'ghost@nowhere.example.com', session_id: sessionId, scope: 'directory',
    });
    expect(impersonated).toBe(401);

    // The caller's own directory resolves without naming an entity.
    const { status, data } = await rawApi('/entities/list', {
      session_id: sessionId, scope: 'directory',
    });
    expect(status).toBe(200);
    expect(data.entities.some((e: any) => e.id === entity_id)).toBe(true);
  });

  test('admin API directory annotates owned vs granted relationships', async () => {
    const myToken = 'adm-dir-me';
    const friendToken = 'adm-dir-friend';
    const myAccount = 'admdirme@example.com';
    const friendAccount = 'admdirfriend@example.com';
    await seedAccount(myAccount, myToken);
    await seedAccount(friendAccount, friendToken);

    const { entity_id: mine } = await createEntity(myToken, 'adm-dir-mine');
    const { entity_id: shared } = await createEntity(friendToken, 'adm-dir-shared');

    const { status: gs } = await api('/admin/api/grants', {
      account_token: friendToken,
      grantee_account_id: myAccount,
      entity_id: shared,
    });
    expect(gs).toBe(201);

    const { status, data } = await api('/admin/api/directory', {
      account_token: myToken,
    });
    expect(status).toBe(200);
    expect(data.total).toBe(2);

    const byId = Object.fromEntries(data.entities.map((e: any) => [e.id, e]));
    expect(byId[mine].relationship).toBe('owned');
    expect(byId[shared].relationship).toBe('granted');
    expect(byId[shared].account_id).toBe(friendAccount);
  });

  // -- Entity List with Pagination ------------------------------------------

  test('entities/list returns entities', async () => {
    const lister = await createEntity(testToken, 'list-caller');
    const { status, data } = await api('/entities/list', {
      entity_id: lister.entity_id, scope: 'online',
    });
    expect(status).toBe(200);
    expect(data.entities).toBeDefined();
    expect(data.total).toBeDefined();
    expect(data.limit).toBeDefined();
  });

  test('entities/list respects pagination', async () => {
    const pager = await createEntity(testToken, 'page-caller');
    const { status, data } = await api('/entities/list', {
      entity_id: pager.entity_id, limit: 1, offset: 0,
    });
    expect(status).toBe(200);
    expect(data.entities.length).toBeLessThanOrEqual(1);
    expect(data.limit).toBe(1);
    expect(data.offset).toBe(0);
  });

  // -- Rate Limiting --------------------------------------------------------

  test('entity rate limiting returns 429', async () => {
    const rlToken = 'rl-token';
    await seedAccount('rlagent@rl.example.com', rlToken);

    const { entity_id } = await createEntity(rlToken, 'rl-agent', 'rl-pk');
    const { entity_id: other } = await createEntity(rlToken, 'rl-other', 'rlo-pk');

    const requests: Promise<{ status: number; data: any }>[] = [];
    for (let i = 0; i < 110; i++) {
      requests.push(
        api('/messages/history', { entity_id, other_entity_id: other })
      );
    }

    const results = await Promise.all(requests);
    const rateLimited = results.filter(r => r.status === 429);

    expect(rateLimited.length).toBeGreaterThan(0);
  });

  // -- Error Handling -------------------------------------------------------

  test('returns 404 for unknown route', async () => {
    const res = await fetch(`${TEST_SERVER_URL}/nonexistent`);
    expect(res.status).toBe(404);
  });

  test('returns 405 for wrong method', async () => {
    const res = await fetch(`${TEST_SERVER_URL}/health`, { method: 'DELETE' });
    expect(res.status).toBe(405);
  });

  // -- Session Enforcement --------------------------------------------------
  //
  // Entity-scoped routes must derive the acting entity from an authenticated
  // session. Reading `entity_id` from the request body makes the entire
  // three-layer auth model decorative: the permission matrix, channel roles
  // and grants all compute correct answers about an unverified subject.

  describe('entity-scoped routes require a session', () => {
    let victim: { entity_id: string; public_key: string; encrypted_key_file: any };
    let attacker: { entity_id: string; public_key: string; encrypted_key_file: any };
    let attackerSession: string;
    let victimSession: string;

    beforeAll(async () => {
      victim = await createEntity(testToken, 'enforce-victim', 'pk', {
        can_send: true,
        can_create_channels: true,
        can_join_channel: true,
      });
      attacker = await createEntity(testToken, 'enforce-attacker', 'pk', {
        can_send: true,
        can_create_channels: true,
        can_join_channel: true,
      });
      attackerSession = await seedSession(attacker.entity_id);
      victimSession = await seedSession(victim.entity_id);
    });

    test('POST /messages/send is rejected without a session', async () => {
      const { status } = await rawApi('/messages/send', {
        entity_id: victim.entity_id,
        to_entity: attacker.entity_id,
        text: 'forged',
      });
      expect(status).toBe(401);
    });

    // The core impersonation: a real session, used to act as somebody else.
    test('POST /messages/send cannot act as an entity the session does not own', async () => {
      const { status } = await rawApi('/messages/send', {
        entity_id: victim.entity_id,
        session_id: attackerSession,
        to_entity: attacker.entity_id,
        text: 'forged',
      });
      expect(status).toBe(401);
    });

    test('POST /messages/history is rejected without a session', async () => {
      const { status } = await rawApi('/messages/history', {
        entity_id: victim.entity_id,
        other_entity_id: attacker.entity_id,
      });
      expect(status).toBe(401);
    });

    test('POST /messages/delivered is rejected without a session', async () => {
      const { status } = await rawApi('/messages/delivered', {
        entity_id: victim.entity_id,
        message_ids: [1],
      });
      expect(status).toBe(401);
    });

    test('POST /channels/create is rejected without a session', async () => {
      const { status } = await rawApi('/channels/create', {
        entity_id: victim.entity_id,
        name: 'forged-channel',
      });
      expect(status).toBe(401);
    });

    test('POST /channels/list-members is rejected without a session', async () => {
      const { status } = await rawApi('/channels/list-members', {
        channel_id: '00000000-0000-4000-8000-000000000000',
      });
      expect(status).toBe(401);
    });

    test('POST /entities/status is rejected without a session', async () => {
      const { status } = await rawApi('/entities/status', {
        entity_id: victim.entity_id,
        status: 'offline',
      });
      expect(status).toBe(401);
    });

    test('POST /entities/list is rejected without a session', async () => {
      const { status } = await rawApi('/entities/list', {});
      expect(status).toBe(401);
    });

    // Enforcement must not break the legitimate path.
    test('a valid session can send as its own entity', async () => {
      const { status } = await rawApi('/messages/send', {
        entity_id: victim.entity_id,
        session_id: victimSession,
        to_entity: attacker.entity_id,
        text: 'legitimate',
      });
      expect(status).toBe(201);
    });

    test('a valid session may omit entity_id entirely — identity comes from the session', async () => {
      const { status } = await rawApi('/messages/send', {
        session_id: victimSession,
        to_entity: attacker.entity_id,
        text: 'identity from session',
      });
      expect(status).toBe(201);
    });

    test('a valid session can create a channel', async () => {
      const { status } = await rawApi('/channels/create', {
        session_id: victimSession,
        name: 'legitimate-channel',
      });
      expect(status).toBe(201);
    });
  });
});
