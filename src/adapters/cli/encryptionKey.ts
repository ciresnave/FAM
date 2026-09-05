// Publishing an entity's encryption key.
//
// ─────────────────────────────────────────────────────────────────────────────
// ⚠️ THIS IS THE STEP WHERE FAM STOPS BEING END-TO-END ENCRYPTED ONLY IN THE
// COMMIT LOG.
//
// `canReceiveSealed` returns false for EVERY ENTITY IN EXISTENCE, because no
// client has ever published an X25519 key. Every primitive, route, storage
// layer and send path is built and merged; the running system has never sealed
// a message. This one POST changes that from a property of the code to a
// property of the deployment.
// ─────────────────────────────────────────────────────────────────────────────
//
// It cannot happen during provisioning: `/entities/encryption-key` requires an
// entity SESSION, and a session needs the identity key to answer a challenge —
// which only exists once the entity has been created. So publishing is
// deliberately a second step, and both CLI creation paths say so rather than
// leaving an entity silently unable to receive sealed mail.
//
// ⚠️ THE KEY COMES FROM THE KEY FILE, NEVER FROM A PARAMETER. A signature
// taking the public key as an argument would let a caller publish something the
// key file cannot decrypt with — an entity advertising a key whose private half
// it does not hold, and every message sent to it permanently unreadable. The
// only source that cannot disagree with itself is the file holding the private
// half.

import { apiRequest } from './client';
import type { CliConfig } from './config';
import { decryptPrivateKey } from '../../crypto/encrypt';
import { readEncryptionKey, readIdentityKey } from './keyMaterial';
import { generateEncryptionKeyPair, bufferToBase64, base64ToBuffer, sign } from '../../crypto/keys';
import type { EncryptedKeyFile } from '../../types';

export interface PublishInput {
  entityId: string;
  keyFile: EncryptedKeyFile;
  passkey: string;
}

export interface PublishResult {
  published: boolean;
  encryptionPublicKey: string;
}

export interface EncryptionKeyStatus {
  hasEncryptionKey: boolean;
  /** Why not, in words a holder can act on. Empty when it has one. */
  reason: string;
}

/**
 * Does this key file carry an encryption key?
 *
 * ⚠️ REPORTS RATHER THAN THROWS for a legacy file. A key file written before
 * encryption keys existed holds only an identity key — that is a true fact
 * about the entity, and the remedy is to generate one. Throwing would present a
 * valid old file as corrupt, and the natural response to "corrupt" is deletion,
 * which destroys the identity it was still holding correctly.
 */
export async function encryptionKeyStatus(
  keyFile: EncryptedKeyFile,
  passkey: string
): Promise<EncryptionKeyStatus> {
  const encryption = readEncryptionKey(await decryptPrivateKey(keyFile, passkey));

  if (encryption === null) {
    return {
      hasEncryptionKey: false,
      reason:
        'This key file predates encryption keys. Generate one to receive sealed messages; ' +
        'the identity key in it is unaffected and still valid.',
    };
  }

  return { hasEncryptionKey: true, reason: '' };
}

/**
 * Derive the public half from the stored private half and register it.
 *
 * ⚠️ REFUSES rather than publishing nothing when the key file has no encryption
 * key. A publish that quietly succeeded having sent no key would leave
 * `canReceiveSealed` false while the caller believes it is true — a silent
 * downgrade wearing a success message, which is the failure this whole series
 * has been removing.
 */
export async function publishEncryptionKey(
  config: CliConfig,
  input: PublishInput
): Promise<PublishResult> {
  const decrypted = await decryptPrivateKey(input.keyFile, input.passkey);
  const encryptionPrivateKey = readEncryptionKey(decrypted);

  if (encryptionPrivateKey === null) {
    throw new Error(
      `${input.entityId} has no encryption key in its key file, so there is nothing to publish. ` +
        `Generate one first — the identity key is unaffected.`
    );
  }

  const encryptionPublicKey = await derivePublicKey(encryptionPrivateKey);

  // ⚠️ AUTHENTICATES ITSELF rather than going through `entityRequest`,
  // which reads whatever credentials happen to be on disk. This function is
  // already given the entity id, the key file and the passkey — everything the
  // challenge needs — so depending on ambient CLI state would add a second
  // source for the same fact, and the two can disagree.
  //
  // It also has to work immediately after provisioning, BEFORE credentials have
  // been saved. A helper that only works once the CLI is fully set up cannot be
  // used at the one moment it is most needed.
  const sessionId = await authenticate(config, input.entityId, input.keyFile, input.passkey);

  try {
    await apiRequest(config, '/entities/encryption-key', {
      entity_id: input.entityId,
      session_id: sessionId,
      encryption_public_key: encryptionPublicKey,
    });
  } finally {
    // Released even on failure. A session left open by a failed publish is a
    // credential outliving the operation that needed it.
    await apiRequest(config, '/entities/disconnect', {
      entity_id: input.entityId,
      session_id: sessionId,
    }).catch(() => {});
  }

  return { published: true, encryptionPublicKey };
}

/**
 * The X25519 public half of a stored private key.
 *
 * ⚠️ DERIVED, NOT STORED ALONGSIDE. Storing both halves would create two values
 * that can disagree — and the disagreement is silent: an entity would advertise
 * one key and decrypt with another, so every message sent to it would be
 * unreadable with nothing failing until someone tried to read one.
 *
 * The `x` field of the exported JWK IS the public key; verified against a
 * generated pair below rather than assumed.
 */
async function derivePublicKey(privateKeyBase64: string): Promise<string> {
  const imported = await crypto.subtle.importKey(
    'pkcs8',
    base64ToBuffer(privateKeyBase64).buffer as ArrayBuffer,
    { name: 'X25519' },
    true,
    ['deriveBits']
  );

  const jwk = (await crypto.subtle.exportKey('jwk', imported)) as unknown as { x?: string };
  if (!jwk.x) {
    throw new Error('Stored encryption key did not yield its public half.');
  }

  return bufferToBase64(new Uint8Array(Buffer.from(jwk.x, 'base64url')));
}

/**
 * Generate an encryption key for an entity whose key file predates them.
 *
 * Returns the new private half for the caller to store; it does NOT write the
 * key file, because rewriting a key file is a destructive operation and the
 * caller is the only party that knows whether it has somewhere to put the
 * result.
 */
export async function generateMissingEncryptionKey(): Promise<{
  privateKey: string;
  publicKey: string;
}> {
  const pair = await generateEncryptionKeyPair();
  return {
    privateKey: bufferToBase64(pair.privateKey),
    publicKey: bufferToBase64(pair.publicKey),
  };
}

/**
 * Run the challenge-response flow and return a session id.
 *
 * The identity private key never leaves this process; only a signature over the
 * server's nonce does.
 */
async function authenticate(
  config: CliConfig,
  entityId: string,
  keyFile: EncryptedKeyFile,
  passkey: string
): Promise<string> {
  const identityPrivateKey = readIdentityKey(await decryptPrivateKey(keyFile, passkey));

  const { nonce } = await apiRequest<{ nonce: string }>(config, '/entities/connect', {
    entity_id: entityId,
    public_key: keyFile.public_key,
  });

  const signature = await sign(base64ToBuffer(nonce), identityPrivateKey);

  const auth = await apiRequest<{ session_id: string }>(config, '/entities/authenticate', {
    entity_id: entityId,
    nonce,
    signature,
  });

  return auth.session_id;
}
