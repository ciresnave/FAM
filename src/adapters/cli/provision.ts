// Provisioning an entity — the client half of entity creation.
//
// ─────────────────────────────────────────────────────────────────────────────
// ⚠️ THE KEY PAIR IS GENERATED HERE, AND THE PASSKEY NEVER LEAVES THIS PROCESS.
//
// `POST /accounts/create-entity` used to mint the Ed25519 pair server-side and
// take the passkey in the request body, so a server compromised at creation
// time obtained BOTH the identity key and the secret protecting every copy of
// it. It could forge that entity's signatures indefinitely and decrypt any key
// file it later came across. Neither was stored — but it held them.
//
// So the private half is created, used and encrypted entirely on this side of
// the wire. The server receives one thing: a public key.
// ─────────────────────────────────────────────────────────────────────────────
//
// ONE implementation, called from both `fam auth login` and `fam entity create`.
// Two copies of a provisioning flow are two places the passkey can start
// travelling again, and the second copy is the one nobody reviews.

import { apiRequest } from './client';
import type { CliConfig } from './config';
import { generateKeyPair, bufferToBase64 } from '../../crypto/keys';
import { encryptPrivateKey } from '../../crypto/encrypt';
import type { EncryptedKeyFile } from '../../types';

interface CreateEntityResponse {
  entity_id: string;
  public_key: string;
}

export interface ProvisionedEntity {
  entity_id: string;
  public_key: string;
  encrypted_key_file: EncryptedKeyFile;
}

/**
 * Generate an identity key pair, register the public half, and encrypt the
 * private half locally under `passkey`.
 *
 * The encryption happens AFTER the round trip because `encryptPrivateKey` binds
 * the file to the entity id, and the id is only settled once the server has
 * assigned it. The private key is in memory throughout and on the wire never.
 */
export async function provisionEntity(
  config: CliConfig,
  accountToken: string,
  name: string,
  type: string,
  passkey: string
): Promise<ProvisionedEntity> {
  const keys = await generateKeyPair();
  const publicKey = bufferToBase64(keys.publicKey);

  const response = await apiRequest<CreateEntityResponse>(config, '/accounts/create-entity', {
    account_token: accountToken,
    name,
    type,
    public_key: publicKey,
  });

  const encryptedKeyFile = await encryptPrivateKey(
    bufferToBase64(keys.privateKey),
    passkey,
    response.entity_id,
    publicKey
  );

  return {
    entity_id: response.entity_id,
    public_key: publicKey,
    encrypted_key_file: encryptedKeyFile,
  };
}
