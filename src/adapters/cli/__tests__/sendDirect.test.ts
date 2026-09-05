import { test, expect, describe, beforeAll, afterAll } from 'bun:test';
import { startServer, stopServer } from '../../../server/http';
import { getDatabaseContext } from '../../../db';
import { hashToken } from '../../../auth/oauth';
import { generateKeyPair, generateEncryptionKeyPair, bufferToBase64 } from '../../../crypto/keys';
import { open } from '../../../crypto/sealing';
import { sendDirect } from '../sendMessage';

// ============================================================================
// ⚠️ SENDING SEALS BY DEFAULT, AND A DOWNGRADE HAS TO BE ASKED FOR.
//
// Publishing made entities REACHABLE by sealed mail. Nothing yet SENT any: the
// CLI called `/messages/send` unconditionally. `canReceiveSealed` was true and
// "a message travelled sealed" was still false — the same gap as before, one
// layer up.
//
// The assertions below are on the DATABASE, not on the return value, for that
// exact reason. A send helper that reports `sealed: true` while the row says
// otherwise is the failure this file exists to catch, and only one of those two
// is what the recipient actually gets.
// ============================================================================

const TEST_PORT = 17971;
const TEST_HOST = '127.0.0.1';
const TEST_SECRET = process.env.FAM_SERVER_SECRET!;

process.env.FAM_PORT = String(TEST_PORT);
process.env.FAM_HOST = TEST_HOST;

const ACCOUNT = 'senddirect@example.com';
const OTHER_ACCOUNT = 'stranger@example.com';
const SENDER = `sender@${ACCOUNT}`;
const SEALED_RECIPIENT = `sealed@${ACCOUNT}`;
const KEYLESS_RECIPIENT = `keyless@${ACCOUNT}`;
const INVISIBLE = `someone@${OTHER_ACCOUNT}`;

const config = { serverUrl: `http://${TEST_HOST}:${TEST_PORT}` } as any;

let serverHandle: ReturnType<typeof startServer>;
let senderIdentityPrivate: string;
let recipientEncryptionPrivate: string;

function sessionFor(entityId: string): string {
  return getDatabaseContext().sessions.create(entityId).id;
}

function messageCount(): number {
  const row = getDatabaseContext()
    .db.prepare('SELECT COUNT(*) as n FROM messages')
    .get() as { n: number };
  return row.n;
}

function lastMessage(): { text: string; sealed: number; to_entity: string } {
  return getDatabaseContext()
    .db.prepare('SELECT text, sealed, to_entity FROM messages ORDER BY id DESC LIMIT 1')
    .get() as any;
}

function baseInput(over: Record<string, unknown> = {}) {
  return {
    senderId: SENDER,
    senderIdentityPrivateKey: senderIdentityPrivate,
    sessionId: sessionFor(SENDER),
    recipientId: SEALED_RECIPIENT,
    text: 'hello there',
    ...over,
  } as any;
}

beforeAll(async () => {
  const ctx = getDatabaseContext();

  for (const acct of [ACCOUNT, OTHER_ACCOUNT]) {
    ctx.db.prepare('INSERT OR IGNORE INTO accounts (id) VALUES (?)').run(acct);
    ctx.db
      .prepare(
        `INSERT OR IGNORE INTO authorizations (id, account_id, server_id, token_hash)
         VALUES (?, ?, 'local', ?)`
      )
      .run(`auth-${acct}`, acct, await hashToken(`token-${acct}`, TEST_SECRET));
  }

  const senderKeys = await generateKeyPair();
  senderIdentityPrivate = bufferToBase64(senderKeys.privateKey);

  const entities: Array<[string, string, Uint8Array]> = [];
  for (const [id, acct] of [
    [SENDER, ACCOUNT],
    [SEALED_RECIPIENT, ACCOUNT],
    [KEYLESS_RECIPIENT, ACCOUNT],
    [INVISIBLE, OTHER_ACCOUNT],
  ] as Array<[string, string]>) {
    const k = id === SENDER ? senderKeys : await generateKeyPair();
    entities.push([id, acct, k.publicKey]);
  }

  for (const [id, acct, pub] of entities) {
    ctx.db
      .prepare(
        `INSERT OR IGNORE INTO entities (id, account_id, type, public_key, capabilities)
         VALUES (?, ?, 'agent', ?, '{"can_send":true,"can_receive":true}')`
      )
      .run(id, acct, bufferToBase64(pub));
  }

  // Only ONE recipient publishes an encryption key. The keyless one is not a
  // broken fixture — it is every entity that existed before publishing shipped.
  const enc = await generateEncryptionKeyPair();
  recipientEncryptionPrivate = bufferToBase64(enc.privateKey);
  ctx.entities.setEncryptionKey(SEALED_RECIPIENT, bufferToBase64(enc.publicKey));

  serverHandle = startServer({ port: TEST_PORT, host: TEST_HOST });
});

afterAll(() => stopServer(serverHandle));

describe('the default path seals', () => {
  test('⚠️ the stored row is sealed and does not contain the plaintext', async () => {
    const outcome = await sendDirect(config, baseInput({ text: 'SENTINEL-BODY-7a21' }));

    expect(outcome.sealed).toBe(true);

    // The database, not the return value. These are two different claims and
    // only this one describes what the recipient receives.
    const row = lastMessage();
    expect(row.sealed).toBe(1);
    expect(row.to_entity).toBe(SEALED_RECIPIENT);
    expect(row.text).not.toContain('SENTINEL-BODY-7a21');
  });

  test('what was stored opens with the recipient private half', async () => {
    // Presence of ciphertext is not correctness. This is the only assertion
    // that proves the message is readable by the intended party and no one
    // else — the same round-trip the publish work ended on.
    await sendDirect(config, baseInput({ text: 'round trip through the server' }));

    const row = lastMessage();
    const envelope = JSON.parse(row.text);
    expect(await open(recipientEncryptionPrivate, envelope.sealed)).toBe(
      'round trip through the server'
    );
  });

  test('sealing is not something the caller had to ask for', async () => {
    // No flag, no option: the input above never mentions sealing. If a future
    // change makes sealing opt-in, this fails.
    const outcome = await sendDirect(config, baseInput());
    expect(outcome.sealed).toBe(true);
    expect(outcome.downgradeReason).toBeUndefined();
  });
});

describe('a recipient with no published key', () => {
  test('⚠️ REFUSES by default, and sends nothing at all', async () => {
    const before = messageCount();

    await expect(
      sendDirect(config, baseInput({ recipientId: KEYLESS_RECIPIENT }))
    ).rejects.toThrow(/encryption key/i);

    // The refusal has to be a refusal. A helper that threw AFTER posting would
    // pass the assertion above while the plaintext was already on the server.
    expect(messageCount()).toBe(before);
  });

  test('sends unsealed only when explicitly allowed, and says so', async () => {
    const outcome = await sendDirect(
      config,
      baseInput({ recipientId: KEYLESS_RECIPIENT, allowPlaintext: true })
    );

    expect(outcome.sealed).toBe(false);
    expect(outcome.downgradeReason).toContain(KEYLESS_RECIPIENT);
    expect(lastMessage().sealed).toBe(0);
  });
});

describe('a recipient the sender cannot see', () => {
  test('⚠️ is an ERROR, never a downgrade — even with plaintext allowed', async () => {
    // THE SUBTLE ONE. "Not in the directory" and "has no key" are different
    // facts, and collapsing them means a lookup failure silently becomes a
    // plaintext send. The recipient may well have a key; the sender just could
    // not see it. Treating that as "no key" downgrades a message that could
    // have been sealed, for a reason that has nothing to do with the recipient.
    const before = messageCount();

    await expect(
      sendDirect(config, baseInput({ recipientId: INVISIBLE, allowPlaintext: true }))
    ).rejects.toThrow(/not visible|not found|cannot see/i);

    expect(messageCount()).toBe(before);
  });
});
