// Account Routes for FAM Server

import type { DatabaseContext } from '../../db/transaction';
import type { Route } from './index';
import {
  getAuthorizationUrl,
  exchangeCodeForToken,
  getUserInfo,
  hashToken,
  generateOAuthState,
  resolveAccountForProvider,
  type OAuthProviderConfig,
} from '../../auth/oauth';
import {
  UnauthorizedError,
  ConflictError,
  NotFoundError,
  ValidationError,
} from '../../types/errors';
import {
  validateAccountId,
  validateEntityId,
  validateEntityType,
} from '../../types/validation';
import { generateKeyPair, bufferToBase64 } from '../../crypto/keys';
import { encryptPrivateKey } from '../../crypto/encrypt';
import { validateAccountToken, requireAccountAuth } from '../middleware/auth';
import { DEFAULT_SERVER_URL } from '../../config';

// ============================================================================
// Configuration
// ============================================================================

const SERVER_SECRET = process.env.FAM_SERVER_SECRET!;
const SERVER_URL = process.env.FAM_SERVER_URL || DEFAULT_SERVER_URL;

const OAUTH_CONFIG: OAuthProviderConfig = {
  google: process.env.GOOGLE_CLIENT_ID
    ? {
        clientId: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
        redirectUri: `${SERVER_URL}/accounts/callback/google`,
      }
    : undefined,
  github: process.env.GITHUB_CLIENT_ID
    ? {
        clientId: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET || '',
        redirectUri: `${SERVER_URL}/accounts/callback/github`,
      }
    : undefined,
};

// ============================================================================
// Account Routes
// ============================================================================

export function accountRoutes(ctx: DatabaseContext): Route[] {
  return [
    // GET /accounts/authorize/:provider
    // Initiates OAuth flow - redirects to provider
    {
      method: 'GET',
      pattern: '/accounts/authorize/:provider',
      handler: async (req, params) => {
        const provider = params.provider as 'google' | 'github';
        
        if (!OAUTH_CONFIG[provider]) {
          return new Response(
            JSON.stringify({ error: `Provider ${provider} not configured` }),
            { status: 400, headers: { 'Content-Type': 'application/json' } }
          );
        }
        
        const state = generateOAuthState();
        
        // Store state in database (persists across restarts)
        ctx.db.run(
          `INSERT OR REPLACE INTO oauth_states (state, provider) VALUES (?, ?)`,
          [state, provider]
        );
        
        const authUrl = getAuthorizationUrl(provider, OAUTH_CONFIG[provider]!, state);
        
        return new Response(null, {
          status: 302,
          headers: { Location: authUrl },
        });
      },
    },
    
    // GET /accounts/callback/:provider
    // OAuth callback - exchanges code for token, creates/returns account
    {
      method: 'GET',
      pattern: '/accounts/callback/:provider',
      handler: async (req, params) => {
        const provider = params.provider as 'google' | 'github';
        const url = new URL(req.url);
        const code = url.searchParams.get('code');
        const state = url.searchParams.get('state');
        
        if (!code || !state) {
          return new Response(
            JSON.stringify({ error: 'Missing code or state parameter' }),
            { status: 400, headers: { 'Content-Type': 'application/json' } }
          );
        }
        
        // Validate state from database
        const stateRow = ctx.db.prepare(
          `SELECT provider FROM oauth_states WHERE state = ?`
        ).get(state) as { provider: string } | undefined;
        
        if (!stateRow || stateRow.provider !== provider) {
          return new Response(
            JSON.stringify({ error: 'Invalid or expired state' }),
            { status: 400, headers: { 'Content-Type': 'application/json' } }
          );
        }
        
        // Exchange code for token (state deletion happens after success)
        const config = OAUTH_CONFIG[provider]!;
        const tokenResponse = await exchangeCodeForToken(provider, config, code);
        
        // Get user info
        const userInfo = await getUserInfo(provider, tokenResponse.access_token);
        
        // Now delete the state (only on success)
        ctx.db.run(`DELETE FROM oauth_states WHERE state = ?`, [state]);
        
        // Resolve the account by PROVIDER IDENTITY, not by email address.
        // getUserInfo has already refused anything the provider has not
        // verified; this additionally refuses a verified address that belongs
        // to an account owned by a different provider identity.
        // Throws AccountProviderMismatchError (403) in that case.
        const accountToken = crypto.randomUUID();
        const accountTokenHash = await hashToken(accountToken, SERVER_SECRET);

        let account: Awaited<ReturnType<typeof resolveAccountForProvider>>;

        ctx.db.run('BEGIN');
        try {
          account = resolveAccountForProvider(
            ctx,
            provider,
            userInfo.id,
            userInfo.email,
            userInfo.name ?? undefined
          );

          // Issue the FAM account token. The provider's own access token is
          // deliberately NOT stored as a FAM credential: it previously was,
          // which made anyone holding the user's Google/GitHub access token
          // able to authenticate to FAM directly. It was then immediately
          // clobbered by this row via UNIQUE(account_id, server_id), so the
          // window was short — but the row should never have existed.
          const accountAuthId = crypto.randomUUID();
          ctx.db.run(
            `INSERT OR REPLACE INTO authorizations (id, account_id, server_id, token_hash, expires_at)
             VALUES (?, ?, ?, ?, datetime('now', '+30 days'))`,
            [accountAuthId, account.id, 'local', accountTokenHash]
          );

          ctx.db.run('COMMIT');
        } catch (e) {
          ctx.db.run('ROLLBACK');
          throw e;
        }
        
        // Return account info and token
        return new Response(
          JSON.stringify({
            account_id: account.id,
            display_name: account.display_name,
            token: accountToken,
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      },
    },
    
    // POST /accounts/create-entity
    // Create a new entity under an account
    {
      method: 'POST',
      pattern: '/accounts/create-entity',
      handler: async (req) => {
        // Identity FIRST, fields second. This route used to answer 400 for a
        // missing account_token before authenticating anything, so "no
        // credential" and "malformed request" were the same reply.
        const { accountId, body } = await requireAccountAuth(ctx, req);
        const { name, type, capabilities, passkey } = body;

        if (!name || !type) {
          return new Response(
            JSON.stringify({ error: 'Missing required fields: name, type' }),
            { status: 400, headers: { 'Content-Type': 'application/json' } }
          );
        }
        
        // Validate inputs
        validateEntityType(type);
        
        // Generate entity ID
        const entityId = `${name}@${accountId}`;
        validateEntityId(entityId);
        
        // Check if entity already exists
        if (ctx.entities.getById(entityId)) {
          throw new ConflictError(`Entity already exists: ${entityId}`);
        }
        
        // Generate key pair
        const keyPair = await generateKeyPair();
        const publicKeyBase64 = bufferToBase64(keyPair.publicKey);
        const privateKeyBase64 = bufferToBase64(keyPair.privateKey);
        
        // Create entity in database
        const entity = ctx.entities.create(
          entityId,
          accountId,
          type,
          publicKeyBase64,
          name,
          capabilities
        );
        
        // Use provided passkey (required for security)
        if (!passkey) {
          throw new ValidationError('Passkey is required for entity creation', 'passkey');
        }
        const entityPasskey = passkey;
        const encryptedKeyFile = await encryptPrivateKey(
          privateKeyBase64,
          entityPasskey,
          entityId,
          publicKeyBase64
        );
        
        return new Response(
          JSON.stringify({
            entity_id: entityId,
            public_key: publicKeyBase64,
            encrypted_key_file: encryptedKeyFile,
          }),
          { status: 201, headers: { 'Content-Type': 'application/json' } }
        );
      },
    },
    
    // POST /accounts/list-entities
    // List all entities for an account
    {
      method: 'POST',
      pattern: '/accounts/list-entities',
      handler: async (req) => {
        const { accountId } = await requireAccountAuth(ctx, req);

        const entities = ctx.entities.getByAccountId(accountId);
        
        return new Response(
          JSON.stringify({ entities }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      },
    },
    
    // POST /accounts/revoke-entity
    // Revoke an entity's access
    {
      method: 'POST',
      pattern: '/accounts/revoke-entity',
      handler: async (req) => {
        const { accountId, body } = await requireAccountAuth(ctx, req);
        const { entity_id } = body;

        if (!entity_id) {
          return new Response(
            JSON.stringify({ error: 'Missing entity_id' }),
            { status: 400, headers: { 'Content-Type': 'application/json' } }
          );
        }
        
        // Verify entity belongs to this account
        const entity = ctx.entities.getById(entity_id);
        if (!entity) {
          throw new NotFoundError('Entity', entity_id);
        }
        
        if (entity.account_id !== accountId) {
          throw new UnauthorizedError('Entity does not belong to this account');
        }
        
        // Delete entity
        ctx.entities.delete(entity_id);
        
        // End all sessions
        ctx.sessions.deleteByEntityId(entity_id);
        
        return new Response(
          JSON.stringify({ ok: true }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      },
    },
  ];
}
