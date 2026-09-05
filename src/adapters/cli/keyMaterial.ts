// An entity's key material — both keypairs, generated and held on this machine.
//
// ─────────────────────────────────────────────────────────────────────────────
// ⚠️ NOTHING IN FAM IS END-TO-END ENCRYPTED IN PRACTICE UNTIL A CLIENT USES
// THIS. Every primitive, route and send path is built and merged; no client has
// ever generated an X25519 pair, so no message has ever been sealed. The commit
// log reads as finished and the running system sends plaintext.
// ─────────────────────────────────────────────────────────────────────────────
//
// TWO KEYPAIRS, NOT ONE, and the reason is not tidiness: Ed25519 signs and
// cannot do ECDH; X25519 does ECDH and cannot sign. Reusing one for both is the
// shortcut `src/crypto/keys.ts` warns about at length — an Ed25519 public key
// imports as X25519 and derives 32 plausible bytes, so the sender produces
// ciphertext the recipient can never open and every check short of testing
// agreement passes.
//
// ⚠️ AND BOTH PRIVATE HALVES GO IN ONE KEY FILE. Two files means two custody
// stories, two passkey prompts, and — the part that actually bites — two
// chances for one to be backed up and the other not. AN ENTITY THAT KEEPS ITS
// SIGNING KEY AND LOSES ITS SEALING KEY CAN PROVE WHO IT IS AND CAN NEVER READ
// ITS OWN MAIL AGAIN. One file, one passkey, one thing to lose.
//
// The server sees neither private half. It gets one public key at creation and
// one more via `/entities/encryption-key`, both public by construction.

import { generateKeyPair, generateEncryptionKeyPair, bufferToBase64 } from '../../crypto/keys';
import { encryptPrivateKey } from '../../crypto/encrypt';
import type { EncryptedKeyFile } from '../../types';

export interface EntityKeyMaterial {
  /** Base64 Ed25519. Signs envelopes and the auth challenge. */
  identityPublicKey: string;
  identityPrivateKey: string;
  /** Base64 X25519. Others seal to this; it never signs anything. */
  encryptionPublicKey: string;
  encryptionPrivateKey: string;
  /**
   * Both private halves, encrypted under the passkey.
   *
   * `public_key` on the file is the IDENTITY key, because `/entities/connect`
   * compares against that field — one field, one meaning. The encryption public
   * key travels separately via its own route.
   */
  keyFile: EncryptedKeyFile;
}

/**
 * The shape stored inside the encrypted blob.
 *
 * A JSON object rather than a bare string, because the file has to carry two
 * keys and a delimiter-joined pair is a parsing decision waiting to be got
 * wrong. Named fields also mean a future third key is an addition rather than
 * a format break.
 */
export interface StoredPrivateKeys {
  identity: string;
  encryption: string;
}

/**
 * Both keypairs, generated but not yet sealed.
 *
 * (This comment previously described `buildEntityKeyMaterial` and was left
 * stranded here when that function moved below — the same orphaning that
 * happened in `messageSend.ts` earlier today. A doc comment attaches to
 * whatever follows it, so moving code past one silently re-points it.)
 */
export interface GeneratedKeys {
  identityPublicKey: string;
  identityPrivateKey: string;
  encryptionPublicKey: string;
  encryptionPrivateKey: string;
}

/**
 * Generate both keypairs. No entity id needed, and nothing is sealed yet.
 *
 * Split from sealing because provisioning is inherently two-phase: the identity
 * PUBLIC key must be sent to create the entity, and the entity id only exists
 * once the server has replied — but `encryptPrivateKey` binds the file to that
 * id. Generating twice to avoid the split would produce an identity key the
 * server has never seen.
 */
export async function generateEntityKeys(): Promise<GeneratedKeys> {
  const identity = await generateKeyPair();
  const encryption = await generateEncryptionKeyPair();

  return {
    identityPublicKey: bufferToBase64(identity.publicKey),
    identityPrivateKey: bufferToBase64(identity.privateKey),
    encryptionPublicKey: bufferToBase64(encryption.publicKey),
    encryptionPrivateKey: bufferToBase64(encryption.privateKey),
  };
}

/** Seal both private halves under `passkey`, bound to `entityId`. */
export async function sealEntityKeys(
  keys: GeneratedKeys,
  passkey: string,
  entityId: string
): Promise<EncryptedKeyFile> {
  const stored: StoredPrivateKeys = {
    identity: keys.identityPrivateKey,
    encryption: keys.encryptionPrivateKey,
  };

  return encryptPrivateKey(JSON.stringify(stored), passkey, entityId, keys.identityPublicKey);
}

/**
 * Generate and seal in one step, for callers that already know the entity id.
 *
 * A composition of the two above rather than a third implementation — the
 * provisioning flow cannot use it, and a second generate/seal path is a second
 * place the two keys could stop travelling together.
 */
export async function buildEntityKeyMaterial(
  passkey: string,
  entityId: string
): Promise<EntityKeyMaterial> {
  const keys = await generateEntityKeys();
  const keyFile = await sealEntityKeys(keys, passkey, entityId);
  return { ...keys, keyFile };
}

/**
 * Read both private halves back out of a key file.
 *
 * ⚠️ TOLERATES THE OLD SINGLE-KEY FORMAT, and says so rather than guessing.
 * Key files written before this change hold a bare base64 identity key, not
 * JSON. Those entities have no encryption key at all — which is a true fact
 * about them, not a parse failure, and reporting it as `null` lets a caller
 * offer to generate one instead of erroring on a file that is perfectly valid
 * for what it was.
 */
export function parseStoredPrivateKeys(decrypted: string): {
  identity: string;
  encryption: string | null;
} {
  const trimmed = decrypted.trim();

  if (!trimmed.startsWith('{')) {
    return { identity: trimmed, encryption: null };
  }

  try {
    const parsed = JSON.parse(trimmed) as Partial<StoredPrivateKeys>;
    if (typeof parsed.identity !== 'string') {
      // JSON that is not OUR json. Reported as unusable rather than silently
      // treated as a legacy blob, because a legacy blob is a valid key and this
      // is not.
      throw new Error('Key file contains JSON without an identity key.');
    }
    return {
      identity: parsed.identity,
      encryption: typeof parsed.encryption === 'string' ? parsed.encryption : null,
    };
  } catch (e) {
    if (e instanceof SyntaxError) {
      throw new Error(
        'Key file looks like JSON but does not parse. It may be truncated or corrupted.'
      );
    }
    throw e;
  }
}
