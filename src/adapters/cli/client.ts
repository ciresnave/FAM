// HTTP Client for CLI Commands

import type { CliConfig } from './config';
import { getServerUrl, getAccountToken, getActiveEntityCredentials } from './config';
import { decryptPrivateKey } from '../../crypto/encrypt';
import { readIdentityKey, readEncryptionKey } from './keyMaterial';
import { sign, base64ToBuffer } from '../../crypto/keys';
import type { EncryptedKeyFile } from '../../types';

// ============================================================================
// Types
// ============================================================================

export interface ApiResponse<T> {
  ok: boolean;
  data?: T;
  error?: string;
  code?: string;
}

// ============================================================================
// Client
// ============================================================================

/**
 * Make an API request to the FAM server.
 */
export async function apiRequest<T>(
  config: CliConfig,
  path: string,
  body?: object
): Promise<T> {
  const serverUrl = await getServerUrl(config);
  
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  
  // Add account token if available
  try {
    const token = await getAccountToken();
    headers['Authorization'] = `Bearer ${token}`;
  } catch {
    // No token yet (e.g., during auth)
  }
  
  const res = await fetch(`${serverUrl}${path}`, {
    method: 'POST',
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  
  if (!res.ok) {
    const err = await res.text();
    let errorData;
    try {
      errorData = JSON.parse(err);
    } catch {
      errorData = { error: err };
    }
    throw new Error(errorData.error || `API error (${res.status}): ${err}`);
  }
  
  return res.json() as Promise<T>;
}

// Entity-scoped routes derive identity from an authenticated session, so the
// CLI needs one before it can send a message or touch a channel. Cached for the
// lifetime of the process: one challenge-response per invocation, not per call.
let cachedSession: { entityId: string; sessionId: string } | null = null;

/**
 * The active entity's identity private key, decrypted with the passkey.
 *
 * ⚠️ EXPORTED SO THERE IS STILL ONLY ONE PLACE THAT DERIVES IT. Signing a
 * sealed envelope needs this key, and `getEntitySession` returns only the
 * session id. Re-deriving it at the send site would be a second route from
 * credentials to a signing key — and the two would agree until one of them
 * stopped going through `readIdentityKey`, which is exactly the bug that broke
 * every key-file consumer once already.
 *
 * NOT cached. The session id is worth holding for the process lifetime; a
 * private key is not, and nothing here needs it more than once per send.
 */
export async function loadIdentityPrivateKey(config: CliConfig): Promise<string> {
  const credentials = await getActiveEntityCredentials();
  const passkey = requirePasskey(config);
  const keyFile: EncryptedKeyFile = JSON.parse(credentials.encrypted_key_file);

  // Through readIdentityKey, never the raw blob: a key file now carries BOTH
  // keys as JSON, and feeding that to a signer fails at key import with an
  // error that points nowhere near the cause.
  return readIdentityKey(await decryptPrivateKey(keyFile, passkey));
}

/**
 * The active entity's encryption private key, or null if it has none.
 *
 * ⚠️ NULL IS A REAL ANSWER AND IS RETURNED AS ONE. An entity whose key file
 * predates encryption keys cannot open sealed mail — a fact about that entity
 * with a remedy, not an error. Throwing here would make an ordinary state
 * indistinguishable from a corrupt key file, and the natural response to
 * "corrupt" is deletion, which destroys the identity key it still holds.
 */
export async function loadEncryptionPrivateKey(config: CliConfig): Promise<string | null> {
  const credentials = await getActiveEntityCredentials();
  const passkey = requirePasskey(config);
  const keyFile: EncryptedKeyFile = JSON.parse(credentials.encrypted_key_file);

  return readEncryptionKey(await decryptPrivateKey(keyFile, passkey));
}

function requirePasskey(config: CliConfig): string {
  const passkey = config.passkey || process.env.FAM_PASSKEY;
  if (!passkey) {
    throw new Error(
      'A passkey is required to authenticate this entity. Pass --passkey or set FAM_PASSKEY.'
    );
  }
  return passkey;
}

/**
 * Establish (or reuse) an entity session: decrypt the private key with the
 * passkey, answer the server's nonce challenge, and keep the session id.
 */
export async function getEntitySession(
  config: CliConfig
): Promise<{ entityId: string; sessionId: string }> {
  const credentials = await getActiveEntityCredentials();

  if (cachedSession && cachedSession.entityId === credentials.entity_id) {
    return cachedSession;
  }

  const passkey = requirePasskey(config);

  const keyFile: EncryptedKeyFile = JSON.parse(credentials.encrypted_key_file);
  const privateKeyBase64 = readIdentityKey(await decryptPrivateKey(keyFile, passkey));

  const { nonce } = await apiRequest<{ nonce: string }>(config, '/entities/connect', {
    entity_id: credentials.entity_id,
    public_key: keyFile.public_key,
  });

  const signature = await sign(base64ToBuffer(nonce), privateKeyBase64);

  const auth = await apiRequest<{ session_id: string }>(config, '/entities/authenticate', {
    entity_id: credentials.entity_id,
    nonce,
    signature,
  });

  cachedSession = { entityId: credentials.entity_id, sessionId: auth.session_id };
  return cachedSession;
}

/**
 * Make an authenticated request with entity context.
 */
export async function entityRequest<T>(
  config: CliConfig,
  path: string,
  extraBody?: object
): Promise<T> {
  const { entityId, sessionId } = await getEntitySession(config);

  return apiRequest<T>(config, path, {
    entity_id: entityId,
    session_id: sessionId,
    ...extraBody,
  });
}
