import { test, expect, describe } from 'bun:test';
import { decryptPrivateKey } from '../../../crypto/encrypt';
import { bufferToBase64, base64ToBuffer, sign, verify } from '../../../crypto/keys';
import { seal, open } from '../../../crypto/sealing';
import { buildEntityKeyMaterial, parseStoredPrivateKeys } from '../keyMaterial';

// ============================================================================
// The client's key material — BOTH keypairs, generated and held locally.
//
// ⚠️ NOTHING IN FAM IS END-TO-END ENCRYPTED IN PRACTICE UNTIL THIS EXISTS.
// Every primitive, route and send path is built and merged; no client has ever
// generated an X25519 pair, so no message has ever been sealed. The commit log
// reads as finished and the running system sends plaintext.
//
// ⚠️ AND THE ENCRYPTION PRIVATE KEY MUST LIVE IN THE SAME PLACE AS THE IDENTITY
// ONE, which is the design decision this file encodes. Two key files means two
// custody stories, two passkey prompts, and — the part that actually bites —
// two chances for one of them to be backed up and the other not. An entity that
// keeps its signing key and loses its sealing key can prove who it is and can
// never read its own mail again.
//
// The server sees neither half. It receives one public key at creation and one
// more via /entities/encryption-key, and both are public by construction.
// ============================================================================

const PASSKEY = 'a-test-passkey';
const ENTITY = 'agent@example.com';

describe('an entity generates both keypairs locally', () => {
  test('the identity key signs and the encryption key seals', async () => {
    // The pair of properties that make two keys necessary rather than tidy:
    // Ed25519 cannot do ECDH, X25519 cannot sign. Asserted together, because
    // either alone is satisfied by a single key that happens to work for one.
    const material = await buildEntityKeyMaterial(PASSKEY, ENTITY);

    const signature = await sign(new TextEncoder().encode('hello'), material.identityPrivateKey);
    expect(await verify(new TextEncoder().encode('hello'), signature, material.identityPublicKey)).toBe(
      true
    );

    const sealed = await seal(material.encryptionPublicKey, 'a secret');
    expect(await open(material.encryptionPrivateKey, sealed)).toBe('a secret');
  });

  test('⚠️ the two keys are DIFFERENT', async () => {
    // Guards against the shortcut the crypto layer warns about: reusing one key
    // for both produces ciphertext the recipient can never open, and every
    // check short of testing agreement passes.
    const material = await buildEntityKeyMaterial(PASSKEY, ENTITY);
    expect(material.identityPublicKey).not.toBe(material.encryptionPublicKey);
    expect(material.identityPrivateKey).not.toBe(material.encryptionPrivateKey);
  });

  test('both private halves are inside ONE encrypted key file', async () => {
    // ⚠️ One file, one passkey, one thing to back up. Two files is two custody
    // stories and two chances for one to be lost — and an entity that keeps its
    // signing key and loses its sealing key can prove who it is while never
    // reading its own mail again.
    const material = await buildEntityKeyMaterial(PASSKEY, ENTITY);

    const recovered = await decryptPrivateKey(material.keyFile, PASSKEY);
    const parsed = JSON.parse(recovered) as { identity: string; encryption: string };

    expect(parsed.identity).toBe(material.identityPrivateKey);
    expect(parsed.encryption).toBe(material.encryptionPrivateKey);
  });

  test('the key file is not readable with the wrong passkey', async () => {
    const material = await buildEntityKeyMaterial(PASSKEY, ENTITY);
    await expect(decryptPrivateKey(material.keyFile, 'wrong-passkey')).rejects.toThrow();
  });

  test('the key file carries the IDENTITY public key, as the auth flow expects', async () => {
    // `/entities/connect` compares against `keyFile.public_key`, so the field
    // has one meaning and it is the identity key. The encryption key travels
    // separately, via /entities/encryption-key.
    const material = await buildEntityKeyMaterial(PASSKEY, ENTITY);
    expect(material.keyFile.public_key).toBe(material.identityPublicKey);
    expect(material.keyFile.entity_id).toBe(ENTITY);
  });

  test('two calls produce different key material', async () => {
    // A constant anywhere in generation would make every entity share a key —
    // the total break that a round-trip test cannot see, since each round trip
    // succeeds against itself.
    const a = await buildEntityKeyMaterial(PASSKEY, ENTITY);
    const b = await buildEntityKeyMaterial(PASSKEY, ENTITY);

    expect(a.identityPublicKey).not.toBe(b.identityPublicKey);
    expect(a.encryptionPublicKey).not.toBe(b.encryptionPublicKey);
  });

  test('⚠️ material from one entity cannot open the other entity mail', async () => {
    // The cross-instance check, which is what actually detects a shared or
    // constant key. Two independent round trips both passing proves only that
    // each is self-consistent.
    const alice = await buildEntityKeyMaterial(PASSKEY, `alice@example.com`);
    const bob = await buildEntityKeyMaterial(PASSKEY, `bob@example.com`);

    const forAlice = await seal(alice.encryptionPublicKey, 'alice only');
    await expect(open(bob.encryptionPrivateKey, forAlice)).rejects.toThrow();
    expect(await open(alice.encryptionPrivateKey, forAlice)).toBe('alice only');
  });
});

describe('the public halves are what the server gets', () => {
  test('both public keys are raw 32-byte base64', async () => {
    // The server validates both with `assertRaw32ByteKey`, so material that did
    // not meet it would be rejected at a route far from here.
    const material = await buildEntityKeyMaterial(PASSKEY, ENTITY);

    for (const key of [material.identityPublicKey, material.encryptionPublicKey]) {
      expect(base64ToBuffer(key).length).toBe(32);
      expect(Buffer.from(key, 'base64').toString('base64').replace(/=+$/, '')).toBe(
        key.replace(/=+$/, '')
      );
    }
  });

  test('no private material appears in what would be sent', async () => {
    // The structural assertion. A helper that returned the wrong field would
    // pass every round-trip test above while leaking the key.
    const material = await buildEntityKeyMaterial(PASSKEY, ENTITY);
    const wire = JSON.stringify({
      public_key: material.identityPublicKey,
      encryption_public_key: material.encryptionPublicKey,
      encrypted_key_file: material.keyFile,
    });

    expect(wire).not.toContain(material.identityPrivateKey);
    expect(wire).not.toContain(material.encryptionPrivateKey);
    expect(wire).not.toContain(PASSKEY);
  });
});

describe('reading key files back, including ones written before this change', () => {
  test('a new key file yields both halves', async () => {
    const material = await buildEntityKeyMaterial(PASSKEY, ENTITY);
    const decrypted = await decryptPrivateKey(material.keyFile, PASSKEY);
    const keys = parseStoredPrivateKeys(decrypted);

    expect(keys.identity).toBe(material.identityPrivateKey);
    expect(keys.encryption).toBe(material.encryptionPrivateKey);
  });

  test('⚠️ a LEGACY file yields the identity key and a null encryption key', async () => {
    // Key files written before this change hold a bare base64 identity key, not
    // JSON. Those entities have no encryption key AT ALL — which is a true fact
    // about them rather than a parse failure.
    //
    // Reporting it as `null` is what lets a caller offer to generate one.
    // Throwing would make a perfectly valid legacy key file look corrupt, and
    // the natural response to "your key file is corrupt" is to delete it —
    // which destroys the identity it was still holding correctly.
    const legacy = bufferToBase64((await import('../../../crypto/keys')).base64ToBuffer('AAAA'));
    const keys = parseStoredPrivateKeys(legacy);

    expect(keys.identity).toBe(legacy);
    expect(keys.encryption).toBeNull();
  });

  test('a real legacy blob round trips through the whole path', async () => {
    // Not a synthetic string: an actual key file in the old format, encrypted
    // and decrypted the way the CLI does it.
    const identity = await (await import('../../../crypto/keys')).generateSerializedKeyPair();
    const legacyFile = await (
      await import('../../../crypto/encrypt')
    ).encryptPrivateKey(identity.privateKey, PASSKEY, ENTITY, identity.publicKey);

    const keys = parseStoredPrivateKeys(await decryptPrivateKey(legacyFile, PASSKEY));

    expect(keys.identity).toBe(identity.privateKey);
    expect(keys.encryption).toBeNull();

    // And the recovered identity key still WORKS — the point of not throwing.
    const sig = await sign(new TextEncoder().encode('x'), keys.identity);
    expect(await verify(new TextEncoder().encode('x'), sig, identity.publicKey)).toBe(true);
  });

  test('⚠️ JSON that is not OUR json is an error, not a legacy blob', async () => {
    // The discriminator is `{` — so a file containing other JSON must not be
    // mistaken for a legacy key. Treating it as one would hand back a "private
    // key" that is really a JSON document, and the failure would surface at a
    // signature check far away.
    expect(() => parseStoredPrivateKeys('{"something":"else"}')).toThrow(/identity/i);
  });

  test('truncated JSON is reported as truncated, not as a legacy key', async () => {
    expect(() => parseStoredPrivateKeys('{"identity":"abc"')).toThrow(/truncated|corrupt/i);
  });
});
