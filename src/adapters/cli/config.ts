// CLI Configuration and Credential Management

import { readFile, writeFile, mkdir, chmod } from 'fs/promises';
import { homedir } from 'os';
import { join } from 'path';
import { stampVersion, assertFormatSupported } from '../../utils/versioning';

// ============================================================================
// Types
// ============================================================================

export interface CliConfig {
  serverUrl: string;
  entityId: string | null;
  passkey: string | null;
}

export interface EntityCredentials {
  entity_id: string;
  encrypted_key_file: string;
  display_name?: string;
}

export interface StoredCredentials {
  /** FAM semver that wrote this file; absent on legacy files. */
  version?: string;
  account_token: string;
  active_entity_id: string;
  entities: EntityCredentials[];
  server_url: string;
}

// ============================================================================
// Paths
// ============================================================================

const FAM_DIR = join(homedir(), '.fam');
const CREDENTIALS_FILE = join(FAM_DIR, 'credentials.json');

// ============================================================================
// Credential Management
// ============================================================================

/**
 * Load stored credentials.
 * @param path Optional credentials file path (defaults to ~/.fam/credentials.json)
 * Handles migration from old single-entity format.
 */
export async function loadCredentials(path?: string): Promise<StoredCredentials | null> {
  try {
    const data = await readFile(path ?? CREDENTIALS_FILE, 'utf-8');
    const parsed = JSON.parse(data);
    
    // Reject files written by a newer FAM before interpreting them
    assertFormatSupported(parsed, 'credentials.json');
    
    // Migrate old format to new format
    if (parsed.entity_id && !parsed.entities) {
      return {
        account_token: parsed.account_token,
        active_entity_id: parsed.entity_id,
        entities: [{
          entity_id: parsed.entity_id,
          encrypted_key_file: parsed.encrypted_key_file,
          display_name: parsed.display_name,
        }],
        server_url: parsed.server_url,
      };
    }
    
    return parsed;
  } catch (e) {
    // Let format errors surface (the file exists but we can't safely read it)
    if (e instanceof Error && e.name === 'UnsupportedFormatVersionError') throw e;
    return null;
  }
}

/**
 * Resolve the active entity's credentials from a credentials file.
 * Throws if the file is missing or the active entity doesn't exist.
 */
export async function getActiveEntityCredentials(path?: string): Promise<EntityCredentials> {
  const credentials = await loadCredentials(path);
  if (!credentials) {
    throw new Error(
      'No FAM credentials found. Run `fam auth` first (or set FAM_CREDENTIALS).'
    );
  }
  
  const entity = credentials.entities.find(e => e.entity_id === credentials.active_entity_id);
  if (!entity) {
    throw new Error(
      `Active entity "${credentials.active_entity_id}" not found in credentials. ` +
      `Available: ${credentials.entities.map(e => e.entity_id).join(', ')}`
    );
  }
  
  return entity;
}

/**
 * Save credentials to disk.
 */
export async function saveCredentials(credentials: StoredCredentials): Promise<void> {
  // This file holds the account token and every entity's encrypted key file —
  // owner-only, never group- or world-readable.
  await mkdir(FAM_DIR, { recursive: true, mode: 0o700 });
  await writeFile(CREDENTIALS_FILE, JSON.stringify(stampVersion(credentials), null, 2), {
    encoding: 'utf-8',
    mode: 0o600,
  });

  // `mode` on mkdir/writeFile only applies when the path is CREATED; an
  // existing directory or file keeps whatever mode it already had. chmod
  // unconditionally so credentials written by an earlier version get tightened
  // on the next save rather than staying world-readable forever.
  // Windows implements only the read-only bit, so this is a near no-op there.
  await chmod(FAM_DIR, 0o700);
  await chmod(CREDENTIALS_FILE, 0o600);
}

/**
 * Add a new entity to credentials or update existing.
 */
export async function addEntityCredentials(
  entityId: string,
  encryptedKeyFile: string,
  config: CliConfig
): Promise<void> {
  const credentials = await loadCredentials();
  const accountToken = await getAccountToken();
  
  if (credentials) {
    // Check if entity already exists
    const existingIndex = credentials.entities.findIndex(e => e.entity_id === entityId);
    if (existingIndex >= 0) {
      credentials.entities[existingIndex].encrypted_key_file = encryptedKeyFile;
    } else {
      credentials.entities.push({ entity_id: entityId, encrypted_key_file: encryptedKeyFile });
    }
    credentials.active_entity_id = entityId;
    await saveCredentials(credentials);
  } else {
    await saveCredentials({
      account_token: accountToken,
      active_entity_id: entityId,
      entities: [{ entity_id: entityId, encrypted_key_file: encryptedKeyFile }],
      server_url: config.serverUrl,
    });
  }
}

/**
 * Switch active entity.
 */
export async function switchEntity(entityId: string): Promise<void> {
  const credentials = await loadCredentials();
  if (!credentials) {
    throw new Error('No credentials found. Run `fam auth` first to authenticate.');
  }
  
  const entity = credentials.entities.find(e => e.entity_id === entityId);
  if (!entity) {
    throw new Error(`Entity "${entityId}" not found. Available entities:\n${
      credentials.entities.map(e => `  ${e.entity_id}`).join('\n')
    }`);
  }
  
  credentials.active_entity_id = entityId;
  await saveCredentials(credentials);
}

/**
 * List all entities in credentials.
 */
export async function listEntityCredentials(): Promise<EntityCredentials[]> {
  const credentials = await loadCredentials();
  return credentials?.entities ?? [];
}

/**
 * Get the active entity ID from credentials or config.
 */
export async function getActiveEntityId(config: CliConfig): Promise<string> {
  if (config.entityId) {
    return config.entityId;
  }
  
  const credentials = await loadCredentials();
  if (!credentials) {
    throw new Error(
      'No credentials found. Run `fam auth` first to authenticate.'
    );
  }
  
  return credentials.active_entity_id;
}

/**
 * Get the account token from credentials.
 */
export async function getAccountToken(): Promise<string> {
  const credentials = await loadCredentials();
  if (!credentials) {
    throw new Error(
      'No credentials found. Run `fam auth` first to authenticate.'
    );
  }
  
  return credentials.account_token;
}

/**
 * Get the server URL from config or credentials.
 */
export async function getServerUrl(config: CliConfig): Promise<string> {
  if (config.serverUrl) {
    return config.serverUrl;
  }
  
  const credentials = await loadCredentials();
  if (credentials?.server_url) {
    return credentials.server_url;
  }
  
  return 'http://127.0.0.1:7899';
}
