import { test, expect, describe, beforeAll, afterAll } from 'bun:test';
import { startServer, stopServer } from '../http';
import { getDatabaseContext } from '../../db';
import { hashToken } from '../../auth/oauth';
import { generateKeyPair, bufferToBase64 } from '../../crypto/keys';

// ============================================================================
// Entity creation must not mint the identity keypair.
//
// ⚠️ WHAT THIS FIXES, measured before the change at `0eacca9`:
// `POST /accounts/create-entity` GENERATED the Ed25519 pair server-side, took
// the PASSKEY in the request body, encrypted the private half with it and
// returned the key file. Neither was stored — `grep private_key src/db/` and
// `grep passkey src/db/` both return nothing — but the server HELD BOTH.
//
// A server compromised at creation time therefore obtained the identity key AND
// the secret protecting every copy of it. It could forge that entity's
// signatures indefinitely, and decrypt any key file it later came across.
//
// ⚠️ AND THE ASYMMETRY IS WHAT MADE IT INVISIBLE. `POST /entities/encryption-key`
// accepts a PUBLIC key only, so FAM never holds an X25519 private half:
// confidentiality from the relay is genuine BY CONSTRUCTION. Identity had no
// such guarantee, so "signed, therefore the relay cannot forge it" was true of
// the mechanism and false of the custody. The crypto review passes; the
// question that finds this is "where does the key come from", which is not a
// crypto question.
//
// The entity now generates its own pair and sends the public half. The server
// receives no private key and no passkey, so there is nothing at creation for a
// compromise to take.
// ============================================================================

const TEST_PORT = 17931;
const TEST_HOST = '127.0.0.1';
const URL_BASE = `http://${TEST_HOST}:${TEST_PORT}`;
const TEST_SECRET = process.env.FAM_SERVER_SECRET!;

process.env.FAM_PORT = String(TEST_PORT);
process.env.FAM_HOST = TEST_HOST;

const ACCOUNT = 'custody@example.com';
const TOKEN = 'custody-token';

let serverHandle: ReturnType<typeof startServer>;

async function post(path: string, body: unknown): Promise<{ status: number; data: any }> {
  const res = await fetch(`${URL_BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, data: await res.json().catch(() => null) };
}

beforeAll(async () => {
  const ctx = getDatabaseContext();
  ctx.db.prepare('INSERT OR IGNORE INTO accounts (id) VALUES (?)').run(ACCOUNT);
  ctx.db
    .prepare(
      `INSERT OR IGNORE INTO authorizations (id, account_id, server_id, token_hash)
       VALUES (?, ?, 'local', ?)`
    )
    .run(`auth-${ACCOUNT}`, ACCOUNT, await hashToken(TOKEN, TEST_SECRET));

  serverHandle = startServer({ port: TEST_PORT, host: TEST_HOST });
});

afterAll(() => stopServer(serverHandle));

describe('the entity brings its own identity key', () => {
  test('a client-generated public key is accepted and stored verbatim', async () => {
    const keys = await generateKeyPair();
    const publicKey = bufferToBase64(keys.publicKey);

    const { status, data } = await post('/accounts/create-entity', {
      account_token: TOKEN,
      name: 'byok',
      type: 'agent',
      public_key: publicKey,
    });

    expect(status).toBe(201);
    expect(data.entity_id).toBe(`byok@${ACCOUNT}`);

    const stored = getDatabaseContext().entities.getById(`byok@${ACCOUNT}`);
    expect(stored!.public_key).toBe(publicKey);
  });

  test('the response carries NO private key material', async () => {
    // The structural assertion. A route that generated a pair and ALSO accepted
    // one would pass the test above while still handing back a key file.
    const keys = await generateKeyPair();

    const { data } = await post('/accounts/create-entity', {
      account_token: TOKEN,
      name: 'noprivate',
      type: 'agent',
      public_key: bufferToBase64(keys.publicKey),
    });

    expect(data).not.toHaveProperty('encrypted_key_file');
    expect(data).not.toHaveProperty('private_key');
    expect(JSON.stringify(data)).not.toContain(bufferToBase64(keys.privateKey));
  });

  test('omitting the public key is REFUSED, not filled in by the server', async () => {
    // ⚠️ The load-bearing test. If the server falls back to generating a pair
    // when none is supplied, the vulnerability is intact for every caller that
    // has not been updated — and those are exactly the callers that would not
    // notice. A silent fallback is the disjunction shape: "client key if
    // supplied, server key otherwise".
    const { status, data } = await post('/accounts/create-entity', {
      account_token: TOKEN,
      name: 'nokey',
      type: 'agent',
    });

    expect(status).toBe(400);
    expect(data.error).toMatch(/public_key/i);
    expect(getDatabaseContext().entities.getById(`nokey@${ACCOUNT}`)).toBeNull();
  });

  test('sending a passkey is REFUSED rather than ignored', async () => {
    // An old client would otherwise transmit the passkey to a server that
    // silently drops it, and keep doing so forever with no signal. Refusing
    // tells it to upgrade — and the passkey is exactly the secret that must
    // stop crossing the wire.
    const keys = await generateKeyPair();

    const { status, data } = await post('/accounts/create-entity', {
      account_token: TOKEN,
      name: 'withpasskey',
      type: 'agent',
      public_key: bufferToBase64(keys.publicKey),
      passkey: 'hunter2',
    });

    expect(status).toBe(400);
    expect(data.error).toMatch(/passkey/i);
    expect(getDatabaseContext().entities.getById(`withpasskey@${ACCOUNT}`)).toBeNull();
  });

  test('a malformed public key is refused', async () => {
    // An Ed25519 public key is exactly 32 bytes. Storing anything else yields an
    // entity whose every signature check fails later, far from here.
    const { status, data } = await post('/accounts/create-entity', {
      account_token: TOKEN,
      name: 'badkey',
      type: 'agent',
      public_key: 'dG9vIHNob3J0',
    });

    expect(status).toBe(400);
    expect(data.error).toMatch(/32 bytes/i);
    expect(getDatabaseContext().entities.getById(`badkey@${ACCOUNT}`)).toBeNull();
  });

  test('a public key that is not valid base64 is refused, even at the right length', async () => {
    // Trips only the encoding arm: Buffer.from SKIPS non-alphabet characters,
    // so 44 valid chars with '!!!' spliced in still decodes to 32 bytes and the
    // length check passes. Same masking the encryption-key route had.
    const valid = Buffer.alloc(32, 5).toString('base64');
    const sneaky = valid.slice(0, 10) + '!!!' + valid.slice(10);
    expect(Buffer.from(sneaky, 'base64').length).toBe(32);

    const { status, data } = await post('/accounts/create-entity', {
      account_token: TOKEN,
      name: 'sneakykey',
      type: 'agent',
      public_key: sneaky,
    });

    expect(status).toBe(400);
    expect(data.error).toMatch(/base64/i);
    expect(getDatabaseContext().entities.getById(`sneakykey@${ACCOUNT}`)).toBeNull();
  });

  test('an unauthenticated call is refused', async () => {
    const keys = await generateKeyPair();
    const { status } = await post('/accounts/create-entity', {
      name: 'noauth',
      type: 'agent',
      public_key: bufferToBase64(keys.publicKey),
    });
    expect(status).toBe(401);
  });
});
