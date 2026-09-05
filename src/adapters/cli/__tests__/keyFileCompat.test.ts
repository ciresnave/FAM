import { test, expect, describe } from 'bun:test';
import { decryptPrivateKey, encryptPrivateKey } from '../../../crypto/encrypt';
import { generateSerializedKeyPair, sign, verify, base64ToBuffer } from '../../../crypto/keys';
import { buildEntityKeyMaterial, readIdentityKey } from '../keyMaterial';

// ============================================================================
// ⚠️ THE BUG THIS FILE EXISTS FOR, FOUND BY READING THE CALLER BEFORE EXTENDING
// IT RATHER THAN BY A FAILING TEST.
//
// `client.ts` did:
//
//     const privateKeyBase64 = await decryptPrivateKey(keyFile, passkey);
//     const signature = await sign(base64ToBuffer(nonce), privateKeyBase64);
//
// It used the decrypted blob DIRECTLY as a signing key. That was correct while
// the blob was a bare base64 key — and the moment a key file carried BOTH keys
// as JSON, every new entity's authentication broke: the JSON string was fed to
// `base64ToBuffer` and the import failed.
//
// ⚠️ MY OWN TESTS DID NOT CATCH IT. They exercised `keyMaterial` in isolation,
// where the round trip is perfect. THE FORMAT CHANGE WAS TESTED; THE READERS OF
// THE FORMAT WERE NOT. A format is a contract between a writer and its readers,
// and testing only the writer tests only half of it.
//
// So these tests go through the reader every consumer now uses, with BOTH
// formats, and assert the recovered key actually SIGNS — not merely that it
// came back as a string.
// ============================================================================

const PASSKEY = 'compat-passkey';
const ENTITY = 'agent@example.com';

describe('every consumer can read both key file formats', () => {
  test('a NEW key file yields an identity key that signs', async () => {
    const material = await buildEntityKeyMaterial(PASSKEY, ENTITY);
    const identity = readIdentityKey(await decryptPrivateKey(material.keyFile, PASSKEY));

    const sig = await sign(base64ToBuffer('AAAA'), identity);
    expect(await verify(base64ToBuffer('AAAA'), sig, material.identityPublicKey)).toBe(true);
  });

  test('a LEGACY key file yields an identity key that signs', async () => {
    // The regression that matters: an entity created before this change must
    // keep authenticating. Breaking it would lock existing users out of their
    // own agents, and the failure would look like a passkey problem.
    const pair = await generateSerializedKeyPair();
    const legacyFile = await encryptPrivateKey(pair.privateKey, PASSKEY, ENTITY, pair.publicKey);

    const identity = readIdentityKey(await decryptPrivateKey(legacyFile, PASSKEY));

    const sig = await sign(base64ToBuffer('AAAA'), identity);
    expect(await verify(base64ToBuffer('AAAA'), sig, pair.publicKey)).toBe(true);
  });

  test('⚠️ the JSON blob is never returned as if it were a key', async () => {
    // The precise defect: `readIdentityKey` must not hand back the whole blob.
    // A test asserting only "a string came back" would have passed against the
    // broken code, because the blob IS a string.
    const material = await buildEntityKeyMaterial(PASSKEY, ENTITY);
    const decrypted = await decryptPrivateKey(material.keyFile, PASSKEY);

    expect(decrypted).toStartWith('{');
    expect(readIdentityKey(decrypted)).not.toStartWith('{');
    expect(readIdentityKey(decrypted)).toBe(material.identityPrivateKey);
  });
});
