import { test, expect, describe, beforeAll, afterAll } from 'bun:test';
import { startServer, stopServer } from '../../../server/http';
import { getDatabaseContext } from '../../../db';
import { hashToken } from '../../../auth/oauth';
import { decryptPrivateKey } from '../../../crypto/encrypt';
import { buildEntityKeyMaterial, readEncryptionKey } from '../keyMaterial';
import { publishEncryptionKey, encryptionKeyStatus } from '../encryptionKey';

// ============================================================================
// ⚠️ THIS IS THE INCREMENT WHERE FAM STOPS BEING END-TO-END ENCRYPTED ONLY IN
// THE COMMIT LOG.
//
// `canReceiveSealed` currently returns false for EVERY ENTITY IN EXISTENCE,
// because no client has ever published an X25519 key. Every primitive, route,
// storage layer and send path is built and merged; the running system has never
// sealed a message. Publishing is the one step that changes that from a
// property of the code to a property of the deployment.
//
// The tests below drive it against a real server rather than a mock, because
// the failure this closes is precisely an integration one: the format was
// tested, the readers were not, and the same shape would repeat if publishing
// were tested against a fake route.
// ============================================================================

const TEST_PORT = 17951;
const TEST_HOST = '127.0.0.1';
const TEST_SECRET = process.env.FAM_SERVER_SECRET!;

process.env.FAM_PORT = String(TEST_PORT);
process.env.FAM_HOST = TEST_HOST;

const ACCOUNT = 'publishkey@example.com';
const TOKEN = 'publishkey-token';
const PASSKEY = 'publish-passkey';
const ENTITY = `agent@${ACCOUNT}`;

let serverHandle: ReturnType<typeof startServer>;
let material: Awaited<ReturnType<typeof buildEntityKeyMaterial>>;

const config = { serverUrl: `http://${TEST_HOST}:${TEST_PORT}`, passkey: PASSKEY } as any;

beforeAll(async () => {
  material = await buildEntityKeyMaterial(PASSKEY, ENTITY);

  const ctx = getDatabaseContext();
  ctx.db.prepare('INSERT OR IGNORE INTO accounts (id) VALUES (?)').run(ACCOUNT);
  ctx.db
    .prepare(
      `INSERT OR IGNORE INTO authorizations (id, account_id, server_id, token_hash)
       VALUES (?, ?, 'local', ?)`
    )
    .run(`auth-${ACCOUNT}`, ACCOUNT, await hashToken(TOKEN, TEST_SECRET));
  ctx.db
    .prepare(
      `INSERT OR IGNORE INTO entities (id, account_id, type, public_key, capabilities)
       VALUES (?, ?, 'agent', ?, '{"can_send":true}')`
    )
    .run(ENTITY, ACCOUNT, material.identityPublicKey);

  serverHandle = startServer({ port: TEST_PORT, host: TEST_HOST });
});

afterAll(() => stopServer(serverHandle));

describe('publishing turns sealing on for an entity', () => {
  test('⚠️ BEFORE publishing, the entity cannot receive sealed messages', async () => {
    // The state every entity in FAM is currently in. Asserted first so the
    // change below is a transition rather than a claim.
    expect(getDatabaseContext().entities.canReceiveSealed(ENTITY)).toBe(false);
  });

  test('publishing registers the key and canReceiveSealed flips', async () => {
    const result = await publishEncryptionKey(config, {
      entityId: ENTITY,
      keyFile: material.keyFile,
      passkey: PASSKEY,
    });

    expect(result.published).toBe(true);
    expect(result.encryptionPublicKey).toBe(material.encryptionPublicKey);

    const ctx = getDatabaseContext();
    expect(ctx.entities.canReceiveSealed(ENTITY)).toBe(true);
    expect(ctx.entities.getEncryptionKey(ENTITY)).toBe(material.encryptionPublicKey);
  });

  test('⚠️ the PUBLIC half is what travels, and only the public half', async () => {
    // The structural assertion. A helper that sent the wrong field would pass
    // the test above — the server would store *a* key and `canReceiveSealed`
    // would report true — while having published a private key.
    const stored = getDatabaseContext().entities.getEncryptionKey(ENTITY);

    expect(stored).toBe(material.encryptionPublicKey);
    expect(stored).not.toBe(material.encryptionPrivateKey);
    expect(stored).not.toBe(material.identityPrivateKey);
  });

  test('publishing twice is idempotent, not an error', async () => {
    // A client that retries after a timeout must not be punished for
    // succeeding. The route overwrites with the same value.
    const again = await publishEncryptionKey(config, {
      entityId: ENTITY,
      keyFile: material.keyFile,
      passkey: PASSKEY,
    });

    expect(again.published).toBe(true);
    expect(getDatabaseContext().entities.getEncryptionKey(ENTITY)).toBe(
      material.encryptionPublicKey
    );
  });
});

describe('an entity whose key file predates encryption keys', () => {
  test('⚠️ is reported as needing one, not as broken', async () => {
    // A legacy key file holds no encryption key. That is a true fact about the
    // entity and the remedy is to generate one — so the status says so rather
    // than throwing, for the same reason the parser reports `null`: the natural
    // response to "corrupt" is deletion, and the file is not corrupt.
    const legacyEntity = `legacy@${ACCOUNT}`;
    const pair = await (await import('../../../crypto/keys')).generateSerializedKeyPair();
    const legacyFile = await (
      await import('../../../crypto/encrypt')
    ).encryptPrivateKey(pair.privateKey, PASSKEY, legacyEntity, pair.publicKey);

    const status = await encryptionKeyStatus(legacyFile, PASSKEY);

    expect(status.hasEncryptionKey).toBe(false);
    expect(status.reason).toMatch(/predates|generate/i);
  });

  test('a current key file reports that it has one', async () => {
    // Control: the status is not "false for everything".
    const status = await encryptionKeyStatus(material.keyFile, PASSKEY);
    expect(status.hasEncryptionKey).toBe(true);
  });

  test('publishing refuses rather than sending nothing', async () => {
    // ⚠️ The failure mode this prevents: a publish that quietly succeeds having
    // sent no key would leave `canReceiveSealed` false while the caller
    // believes it is true — a silent downgrade wearing a success message.
    const legacyEntity = `legacy2@${ACCOUNT}`;
    const pair = await (await import('../../../crypto/keys')).generateSerializedKeyPair();
    const legacyFile = await (
      await import('../../../crypto/encrypt')
    ).encryptPrivateKey(pair.privateKey, PASSKEY, legacyEntity, pair.publicKey);

    await expect(
      publishEncryptionKey(config, {
        entityId: legacyEntity,
        keyFile: legacyFile,
        passkey: PASSKEY,
      })
    ).rejects.toThrow(/no encryption key/i);
  });
});

describe('the key file is the source, not a parameter', () => {
  test('the published key comes from the key file, not from the caller', async () => {
    // A signature taking the key as an argument would let a caller publish
    // something the key file cannot decrypt with — an entity advertising a key
    // whose private half it does not hold, and every message to it lost.
    const decrypted = await decryptPrivateKey(material.keyFile, PASSKEY);
    expect(readEncryptionKey(decrypted)).toBe(material.encryptionPrivateKey);

    const published = getDatabaseContext().entities.getEncryptionKey(ENTITY);
    const sealed = await (
      await import('../../../crypto/sealing')
    ).seal(published!, 'round trip');

    // The decisive check: what the SERVER now advertises can be opened by the
    // private half in the LOCAL key file. Anything else means the entity
    // published a key it cannot use.
    expect(
      await (await import('../../../crypto/sealing')).open(material.encryptionPrivateKey, sealed)
    ).toBe('round trip');
  });
});
