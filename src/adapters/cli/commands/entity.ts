// Entity Commands - Create, List, Manage Entities

import { apiRequest, entityRequest } from '../client';
import {
  addEntityCredentials,
  switchEntity,
  listEntityCredentials,
  getAccountToken,
  getActiveEntityCredentials,
  type CliConfig,
} from '../config';
import { decryptPrivateKey } from '../../../crypto/encrypt';
import { sign, base64ToBuffer } from '../../../crypto/keys';
import type { EncryptedKeyFile } from '../../../types';

// ============================================================================
// Types
// ============================================================================

interface Entity {
  id: string;
  account_id: string;
  type: string;
  display_name: string | null;
  capabilities: Record<string, boolean>;
  created_at: string;
  last_seen: string | null;
}

interface CreateEntityResponse {
  entity_id: string;
  encrypted_key_file: string;
  public_key: string;
}

// ============================================================================
// Entity Command Router
// ============================================================================

export async function runEntityCommand(
  subcommand: string | null,
  positional: string[],
  flags: Record<string, string | boolean>,
  config: CliConfig
): Promise<void> {
  switch (subcommand) {
    case 'create':
      await createEntity(positional, flags, config);
      break;
      
    case 'list':
      await listEntities(config);
      break;
      
    case 'switch':
      await switchToEntity(positional, config);
      break;
      
    case 'availability':
      await setAvailabilityCommand(positional, config);
      break;
      
    default:
      console.log('Usage: fam entity <create|list|switch|availability>');
      console.log('');
      console.log('Commands:');
      console.log('  create <name>   Create a new entity');
      console.log('  list            List your entities');
      console.log('  switch <id>     Switch active entity');
      console.log('  availability <available|unavailable>');
      console.log('                  Pause or resume incoming messages');
      break;
  }
}

// ============================================================================
// Create Entity
// ============================================================================

async function createEntity(
  positional: string[],
  flags: Record<string, string | boolean>,
  config: CliConfig
): Promise<void> {
  const name = positional[0];
  if (!name) {
    throw new Error('Usage: fam entity create <name> [--type agent|human|tool] [--passkey <key>]');
  }
  
  const type = (flags.type as string) || 'human';
  const passkey = (flags.passkey as string) || config.passkey || await promptPasskey();
  
  const accountToken = await getAccountToken();
  
  console.log(`Creating entity: ${name}@... (type: ${type})`);
  
  const response = await apiRequest<CreateEntityResponse>(config, '/accounts/create-entity', {
    account_token: accountToken,
    name,
    type,
    passkey,
  });
  
  console.log(`\nEntity created: ${response.entity_id}`);
  
  // Save credentials for this entity
  await addEntityCredentials(response.entity_id, response.encrypted_key_file, config);
  
  console.log(`Credentials saved. You can now use this entity with FAM commands.`);
}

// ============================================================================
// Switch Entity
// ============================================================================

async function switchToEntity(
  positional: string[],
  config: CliConfig
): Promise<void> {
  const entityId = positional[0];
  
  if (!entityId) {
    // List available entities
    const entities = await listEntityCredentials();
    if (entities.length === 0) {
      console.log('No entities found. Run `fam entity create <name>` first.');
      return;
    }
    
    console.log('Available entities:');
    for (const entity of entities) {
      console.log(`  ${entity.entity_id}`);
    }
    console.log('');
    console.log('Usage: fam entity switch <entity_id>');
    return;
  }
  
  await switchEntity(entityId);
  console.log(`Switched to entity: ${entityId}`);
}

// ============================================================================
// Set Availability
// ============================================================================

async function setAvailabilityCommand(
  positional: string[],
  config: CliConfig
): Promise<void> {
  const availability = positional[0];
  
  if (!availability || !['available', 'unavailable'].includes(availability)) {
    throw new Error('Usage: fam entity availability <available|unavailable>');
  }
  
  // Availability requires a valid session, so the CLI performs the full
  // entity auth flow: decrypt key → connect → sign nonce → authenticate.
  const credentials = await getActiveEntityCredentials();
  const keyFile: EncryptedKeyFile = JSON.parse(credentials.encrypted_key_file);
  
  const passkey = config.passkey || await promptPasskey();
  
  console.error('Authenticating...'); // stderr keeps stdout clean
  
  const privateKeyBase64 = await decryptPrivateKey(keyFile, passkey);
  
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
  
  try {
    const result = await apiRequest<{ ok: boolean; availability: string; messages_pushed: number }>(
      config,
      '/entities/availability',
      {
        entity_id: credentials.entity_id,
        session_id: auth.session_id,
        availability,
      }
    );
    
    const suffix = availability === 'available' && result.messages_pushed > 0
      ? ` (${result.messages_pushed} queued message(s) will be pushed)`
      : '';
    console.log(`Availability set to: ${availability}${suffix}`);
    if (availability === 'unavailable') {
      console.log('Incoming message pushes are paused. Queued messages deliver when you become available.');
    }
  } finally {
    // Always release the session
    await apiRequest(config, '/entities/disconnect', {
      entity_id: credentials.entity_id,
      session_id: auth.session_id,
    }).catch(() => {});
  }
}

// ============================================================================
// List Entities
// ============================================================================

async function listEntities(config: CliConfig): Promise<void> {
  const response = await entityRequest<{ entities: Entity[] }>(config, '/entities/list', {});
  
  const entities = response.entities;
  
  if (entities.length === 0) {
    console.log('No entities found.');
    return;
  }
  
  console.log(`\nEntities (${entities.length}):\n`);
  
  for (const entity of entities) {
    const status = entity.last_seen ? 'online' : 'offline';
    const capabilities = Object.entries(entity.capabilities)
      .filter(([_, v]) => v)
      .map(([k]) => k)
      .join(', ');
    
    console.log(`  ${entity.id}`);
    console.log(`    Type: ${entity.type}`);
    console.log(`    Status: ${status}`);
    if (entity.display_name) {
      console.log(`    Name: ${entity.display_name}`);
    }
    if (capabilities) {
      console.log(`    Capabilities: ${capabilities}`);
    }
    console.log(`    Created: ${entity.created_at}`);
    console.log('');
  }
}

// ============================================================================
// Helpers
// ============================================================================

async function promptPasskey(): Promise<string> {
  const readline = await import('readline');
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stderr,
  });
  
  return new Promise((resolve) => {
    rl.question('Enter passkey for encrypting private key: ', (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}
