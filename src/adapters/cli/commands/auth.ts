// Auth Command - OAuth Authentication Flow
//
// Opens browser for OAuth, handles callback, saves credentials.

import { provisionEntity } from '../provision';
import { createServer } from 'http';
import { URL } from 'url';
import { apiRequest } from '../client';
import { saveCredentials, loadCredentials, type CliConfig } from '../config';
import { DEFAULT_SERVER_URL } from '../../../config';

// ============================================================================
// Types
// ============================================================================

interface CallbackResponse {
  account_id: string;
  display_name: string | null;
  token: string;
}

// ============================================================================
// OAuth Configuration
// ============================================================================

const OAUTH_CONFIGS: Record<string, { authUrl: string; callbackPath: string }> = {
  google: {
    authUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    callbackPath: '/accounts/callback/google',
  },
  github: {
    authUrl: 'https://github.com/login/oauth/authorize',
    callbackPath: '/accounts/callback/github',
  },
};

// ============================================================================
// Auth Command
// ============================================================================

export async function runAuthCommand(
  subcommand: string | null,
  flags: Record<string, string | boolean>,
  config: CliConfig
): Promise<void> {
  const provider = (flags.provider as string) || 'google';
  
  if (subcommand === 'logout') {
    // TODO: Implement logout
    console.log('Logout not yet implemented');
    return;
  }
  
  const oauthConfig = OAUTH_CONFIGS[provider];
  if (!oauthConfig) {
    throw new Error(`Unsupported provider: ${provider}. Use google or github.`);
  }
  
  console.log(`Starting OAuth flow with ${provider}...`);
  
  // 1. Generate state parameter
  const state = crypto.randomUUID();
  
  // 2. Start local callback server
  const callbackPort = 8901;
  
  console.log(`\nOpening browser for authentication...`);
  console.log(`If the browser doesn't open, visit:`);
  console.log(`\n  ${config.serverUrl}/accounts/authorize/${provider}\n`);
  console.log(`Waiting for callback on port ${callbackPort}...`);
  
  // 3. Start local server to catch callback
  const { token, account_id: accountId, display_name: displayName } = await new Promise<CallbackResponse>((resolve, reject) => {
    const server = createServer(async (req, res) => {
      try {
        const url = new URL(req.url || '/', `http://localhost:${callbackPort}`);
        const code = url.searchParams.get('code');
        const returnedState = url.searchParams.get('state');
        
        if (!code || !returnedState) {
          res.writeHead(400, { 'Content-Type': 'text/html' });
          res.end('<h1>Missing code or state</h1>');
          return;
        }
        
        if (returnedState !== state) {
          res.writeHead(400, { 'Content-Type': 'text/html' });
          res.end('<h1>Invalid state parameter</h1>');
          return;
        }
        
        // Exchange code with FAM server
        const serverUrl = config.serverUrl || DEFAULT_SERVER_URL;
        const redirectUrl = `${serverUrl}${oauthConfig.callbackPath}?code=${code}&state=${returnedState}`;
        
        const response = await fetch(redirectUrl);
        const data = await response.json() as CallbackResponse;
        
        // Send success page
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(`
          <html>
          <body>
            <h1>Authentication Successful!</h1>
            <p>Account: ${data.account_id}</p>
            <p>You can close this window and return to the terminal.</p>
          </body>
          </html>
        `);
        
        server.close();
        resolve(data);
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'text/html' });
        res.end('<h1>Authentication failed</h1>');
        server.close();
        reject(e);
      }
    });
    
    server.listen(callbackPort, () => {
      // Open browser to FAM server authorize endpoint (which redirects to OAuth provider)
      const serverUrl = config.serverUrl || DEFAULT_SERVER_URL;
      const authUrl = `${serverUrl}/accounts/authorize/${provider}`;
      
      // Try to open browser
      const platform = process.platform;
      if (platform === 'darwin') {
        Bun.spawn(['open', authUrl]);
      } else if (platform === 'win32') {
        Bun.spawn(['start', authUrl]);
      } else {
        Bun.spawn(['xdg-open', authUrl]);
      }
    });
    
    // Timeout after 5 minutes
    setTimeout(() => {
      server.close();
      reject(new Error('Authentication timed out after 5 minutes'));
    }, 5 * 60 * 1000);
  });
  
  console.log(`\nAuthenticated as: ${accountId}${displayName ? ` (${displayName})` : ''}`);
  
  // 4. Create entity
  console.log(`\nCreating entity...`);
  
  const passkey = config.passkey || await promptPasskey();
  
  // Use hostname as entity name (configurable via --name flag)
  const entityName = (flags.name as string) || require('os').hostname();
  
  // Key pair generated HERE; the passkey never leaves this process.
  // See src/adapters/cli/provision.ts.
  const entityData = await provisionEntity(config, token, entityName, 'human', passkey);
  
  console.log(`Entity created: ${entityData.entity_id}`);
  
  // 5. Save credentials (merge with existing entities to avoid data loss)
  const existing = await loadCredentials();
  const previousEntities = existing?.entities ?? [];
  const filtered = previousEntities.filter(
    e => e.entity_id !== entityData.entity_id
  );
  
  await saveCredentials({
    account_token: token,
    active_entity_id: entityData.entity_id,
    entities: [
      ...filtered,
      {
        entity_id: entityData.entity_id,
        // Stringified because the credential store holds a JSON STRING and
        // client.ts reads it back with JSON.parse. The server used to return an
        // object here and it was stored unserialised into a string-typed field,
        // so JSON.parse got "[object Object]" and threw — every CLI command
        // needing an entity session was broken after `fam auth login`. The
        // type error that surfaced it only appeared once provisioning moved
        // client-side and the value stopped being `any`.
        encrypted_key_file: JSON.stringify(entityData.encrypted_key_file),
      },
    ],
    server_url: config.serverUrl || DEFAULT_SERVER_URL,
  });
  
  // ⚠️ SAID OUT LOUD, because the alternative is an entity that silently cannot
  // receive sealed messages. The encryption key exists locally but the server
  // has not been told — publishing needs an entity session, which does not
  // exist yet. `canReceiveSealed` reports false until then.
  console.log('Encryption key generated locally. It is NOT yet published,');
  console.log('so this entity cannot receive sealed messages until it');
  console.log('authenticates and publishes it.');

  console.log(`\nCredentials saved to ~/.fam/credentials.json`);
  console.log(`\nYou can now use FAM commands:`);
  console.log(`  fam send someone@email.com "Hello!"`);
  console.log(`  fam channels list`);
  console.log(`  fam history`);
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
