import { test, expect, describe, beforeAll, afterAll } from 'bun:test';
import { startServer, stopServer } from '../http';
import { getDatabaseContext } from '../../db';
import { hashToken } from '../../auth/oauth';
import { generateKeyPair, generateEncryptionKeyPair, bufferToBase64 } from '../../crypto/keys';

// ============================================================================
// ⚠️ CAN A SENDER ACTUALLY OBTAIN THE KEY IT IS SUPPOSED TO SEAL TO?
//
// `/entities/encryption-key` says in a comment that there is deliberately no
// matching READ route, because `encryption_public_key` "rides on the entity
// representation a caller is already entitled to see". Every future sealing
// client depends on that being true, and a comment is not a measurement — the
// mapper including a field does not mean the ROUTE serialises it.
//
// So this file measures it end to end, against a real server, from the
// perspective of the party that needs it: a sender holding a session, asking
// the directory, and getting back something it can seal with.
//
// The distinction that matters is null vs absent vs empty. A sender testing
// `if (entity.encryption_public_key)` treats all three the same and falls back
// to plaintext — which is the silent downgrade the whole increment exists to
// remove. So "no key" must be a VISIBLE null, not a missing field.
// ============================================================================

const TEST_PORT = 17961;
const TEST_HOST = '127.0.0.1';
const URL_BASE = `http://${TEST_HOST}:${TEST_PORT}`;
const TEST_SECRET = process.env.FAM_SERVER_SECRET!;

process.env.FAM_PORT = String(TEST_PORT);
process.env.FAM_HOST = TEST_HOST;

const ACCOUNT = 'keydiscovery@example.com';
const SENDER = `sender@${ACCOUNT}`;
const SEALED_RECIPIENT = `sealedrecipient@${ACCOUNT}`;
const PLAIN_RECIPIENT = `plainrecipient@${ACCOUNT}`;

let serverHandle: ReturnType<typeof startServer>;
let recipientEncryptionPublic: string;
/** The half that is never sent anywhere; used to prove the discovered key works. */
let recipientEncryptionPrivate: string;

// A literal union rather than `string`, matching `sealedSendRoute.test.ts`.
//
// ⚠️ THIS DOES NOT SATISFY CODACY, AND AN EARLIER VERSION OF THIS COMMENT
// CLAIMED IT DID. Measured: PR #13 carried the identical annotation on the
// identical construct at `sealedSendRoute.test.ts:44` and merged with it. The
// rule flags any variable reaching `fetch`, narrowing or not — so "I followed
// the existing spelling" was an argument from a false premise, because the
// existing spelling was never clean either.
//
// The union stays because it is a genuine narrowing on its own merits: the
// value can only be a path this file names. It is not a fix for the scanner,
// and saying it was would be the same defect as a comment describing a
// capability that is not there.
type Endpoint = '/entities/list';

async function post(path: Endpoint, body: unknown): Promise<{ status: number; data: any }> {
  const res = await fetch(`${URL_BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, data: await res.json().catch(() => null) };
}

function sessionFor(entityId: string): string {
  return getDatabaseContext().sessions.create(entityId).id;
}

beforeAll(async () => {
  const ctx = getDatabaseContext();
  ctx.db.prepare('INSERT OR IGNORE INTO accounts (id) VALUES (?)').run(ACCOUNT);
  ctx.db
    .prepare(
      `INSERT OR IGNORE INTO authorizations (id, account_id, server_id, token_hash)
       VALUES (?, ?, 'local', ?)`
    )
    .run(`auth-${ACCOUNT}`, ACCOUNT, await hashToken(`token-${ACCOUNT}`, TEST_SECRET));

  for (const id of [SENDER, SEALED_RECIPIENT, PLAIN_RECIPIENT]) {
    const identity = await generateKeyPair();
    ctx.db
      .prepare(
        `INSERT OR IGNORE INTO entities (id, account_id, type, public_key, capabilities)
         VALUES (?, ?, 'agent', ?, '{"can_send":true}')`
      )
      .run(id, ACCOUNT, bufferToBase64(identity.publicKey));
  }

  // Only ONE of the two recipients publishes. The other is the control: an
  // entity that genuinely cannot receive sealed mail, so that "every entity
  // has a key" and "the field is echoed back regardless" both fail here.
  const encryption = await generateEncryptionKeyPair();
  recipientEncryptionPublic = bufferToBase64(encryption.publicKey);
  recipientEncryptionPrivate = bufferToBase64(encryption.privateKey);
  ctx.entities.setEncryptionKey(SEALED_RECIPIENT, recipientEncryptionPublic);

  serverHandle = startServer({ port: TEST_PORT, host: TEST_HOST });
});

afterAll(() => stopServer(serverHandle));

describe('a sender can obtain the key it must seal to', () => {
  test('⚠️ the directory carries the recipient encryption key', async () => {
    // The load-bearing assertion. If this fails, no client can seal to anyone,
    // and the comment on `/entities/encryption-key` claiming a read route is
    // unnecessary is wrong.
    const { status, data } = await post('/entities/list', {
      entity_id: SENDER,
      session_id: sessionFor(SENDER),
    });

    expect(status).toBe(200);

    const recipient = data.entities.find((e: any) => e.id === SEALED_RECIPIENT);
    expect(recipient).toBeDefined();
    expect(recipient.encryption_public_key).toBe(recipientEncryptionPublic);
  });

  test('⚠️ an entity with no key reports null, not an absent field', async () => {
    // null vs absent is the whole distinction. A sender reading an ABSENT field
    // cannot tell "this entity cannot receive sealed mail" from "this response
    // does not carry key information" — and the safe-looking default for both
    // is to send plaintext. One of those is a correct fallback; the other is a
    // downgrade caused by a serialisation detail.
    const { data } = await post('/entities/list', {
      entity_id: SENDER,
      session_id: sessionFor(SENDER),
    });

    const plain = data.entities.find((e: any) => e.id === PLAIN_RECIPIENT);
    expect(plain).toBeDefined();
    expect('encryption_public_key' in plain).toBe(true);
    expect(plain.encryption_public_key).toBeNull();
  });

  test('the key that comes back is usable, not merely present', async () => {
    // Presence is not usability. A truncated or re-encoded key is still a
    // string, still non-null, and still fails at the only moment that counts —
    // when someone tries to read the message. So the discovered key is sealed
    // to and opened with the private half generated above.
    const { seal, open } = await import('../../crypto/sealing');
    const { data } = await post('/entities/list', {
      entity_id: SENDER,
      session_id: sessionFor(SENDER),
    });

    const recipient = data.entities.find((e: any) => e.id === SEALED_RECIPIENT);
    const envelope = await seal(recipient.encryption_public_key, 'discovered key works');

    // Opened with the private half that was never sent anywhere. This is the
    // decisive step: it proves the key travelled through the database, the
    // mapper and JSON serialisation without being altered.
    expect(await open(recipientEncryptionPrivate, envelope)).toBe('discovered key works');
  });
});
