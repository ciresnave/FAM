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
  assertRaw32ByteKey,
  validateAccountId,
  validateEntityId,
  validateEntityType,
} from '../../types/validation';
// ⚠️ DELIBERATELY NO KEY-GENERATION OR KEY-ENCRYPTION IMPORTS HERE.
//
// This file used to import `generateKeyPair` and `encryptPrivateKey` and mint
// an entity's identity pair server-side. Removing the CALLS was not enough:
// leaving the imports in scope means the next edit can reach for them without
// anyone noticing what property that costs.
//
// The guarantee this route now provides — the server never holds an entity's
// private key — is meant to be structural, in the shape `/entities/encryption-key`
// already had: it accepts a PUBLIC key and there is no code path by which a
// private one could arrive. An unused import is the difference between a
// type-level guarantee and a comment asking people not to.
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
        const { name, type, capabilities, public_key, passkey } = body;

        if (!name || !type) {
          return new Response(
            JSON.stringify({ error: 'Missing required fields: name, type' }),
            { status: 400, headers: { 'Content-Type': 'application/json' } }
          );
        }

        // ⚠️ REFUSED, NOT IGNORED. The passkey used to be sent here so the
        // server could encrypt a key file it had just minted. It must never
        // cross the wire again — it is the secret protecting every copy of the
        // private key. An old client that keeps sending it to a server which
        // silently drops it would keep doing so forever with no signal.
        if (passkey !== undefined) {
          return new Response(
            JSON.stringify({
              error:
                'passkey must not be sent to the server. Generate the key pair locally, ' +
                'encrypt it with the passkey on your own machine, and send only public_key.',
            }),
            { status: 400, headers: { 'Content-Type': 'application/json' } }
          );
        }

        // ⚠️ REQUIRED, WITH NO SERVER-SIDE FALLBACK. Generating a pair when
        // none is supplied would leave the vulnerability intact for exactly the
        // callers that had not been updated — the ones who would not notice.
        // "Client key if supplied, server key otherwise" is the disjunction
        // shape, and here it silently restores the property being removed.
        if (typeof public_key !== 'string' || public_key === '') {
          return new Response(
            JSON.stringify({
              error:
                'public_key is required: the entity generates its own Ed25519 key pair and ' +
                'sends the public half. The server no longer mints identity keys.',
            }),
            { status: 400, headers: { 'Content-Type': 'application/json' } }
          );
        }

        // One shared validator rather than a local copy. See
        // assertRaw32ByteKey: three of these existed and a fourth was about to
        // be written, and identical copies are cheap to collapse only until
        // they diverge.
        try {
          assertRaw32ByteKey(public_key, {
            field: 'public_key',
            why: 'It is the raw Ed25519 key the entity generated.',
          });
        } catch (e) {
          return new Response(
            JSON.stringify({ error: e instanceof Error ? e.message : 'Invalid public_key' }),
            { status: 400, headers: { 'Content-Type': 'application/json' } }
          );
        }

        const entityId = `${name}@${accountId}`;
        validateEntityId(entityId);

        if (ctx.entities.getById(entityId)) {
          throw new ConflictError(`Entity already exists: ${entityId}`);
        }

        // The entity's public key, verbatim. THE SERVER NEVER SEES A PRIVATE
        // HALF — which is what makes an envelope signature mean something the
        // relay could not have produced.
        ctx.entities.create(entityId, accountId, type, public_key, name, capabilities);

        // No key file in the response, because there is nothing to put in one.
        // The caller already holds the private key it generated and encrypts it
        // locally under a passkey the server never learns.
        return new Response(
          JSON.stringify({
            entity_id: entityId,
            public_key,
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
