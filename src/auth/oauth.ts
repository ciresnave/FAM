// OAuth 2.0 Handlers for Account Authentication
//
// Supports Google and GitHub as identity providers.

import { hashSha256 } from '../crypto/keys';
import type { DatabaseContext } from '../db/transaction';
import type { Account } from '../types';
import { AccountProviderMismatchError, UnverifiedEmailError } from '../types/errors';

// ============================================================================
// Account Identity Resolution
// ============================================================================

/**
 * Pick the address the provider has actually verified.
 *
 * FAM derives the account id from this address, so an unverified one is an
 * attacker-controlled string. GitHub's `/user` endpoint returns the user's
 * PUBLIC PROFILE email — a free-text field the user sets and GitHub never
 * verifies — so it is ignored entirely in favour of `/user/emails`.
 *
 * Throws rather than falling back. There is no safe default here: the previous
 * `${login}@github.com` fallback minted an address in a domain nobody controls.
 */
export function selectVerifiedEmail(
  provider: 'google' | 'github',
  profile: Record<string, any>,
  emails?: Array<{ email?: string; primary?: boolean; verified?: boolean }>
): string {
  if (provider === 'google') {
    // oauth2/v2/userinfo spells it `verified_email`; the OIDC userinfo endpoint
    // spells it `email_verified`. Accept either so swapping endpoints cannot
    // silently turn the check off.
    const verified = profile.verified_email ?? profile.email_verified;
    if (verified !== true && verified !== 'true') {
      throw new UnverifiedEmailError('Google');
    }
    if (!profile.email) throw new UnverifiedEmailError('Google');
    return String(profile.email);
  }

  const candidates = emails ?? [];
  const verified = candidates.filter((e) => e.verified === true && e.email);
  // Prefer the primary address; fall back to any verified one so a user whose
  // primary is unverified can still sign in with an address they do own.
  const chosen = verified.find((e) => e.primary === true) ?? verified[0];
  if (!chosen?.email) throw new UnverifiedEmailError('GitHub');
  return String(chosen.email);
}

/**
 * Resolve the account for a provider identity, creating it on first sight.
 *
 * Resolution is by (provider, provider_account_id) — the provider's own stable
 * user id, which the user cannot choose — NOT by email. Matching on email alone
 * meant anyone who could present the same email string at any provider claimed
 * the account, and GitHub profile emails are freely settable.
 *
 * Throws AccountProviderMismatchError when the email belongs to an account
 * owned by a different provider identity.
 */
export function resolveAccountForProvider(
  ctx: DatabaseContext,
  provider: 'google' | 'github',
  providerAccountId: string,
  email: string,
  displayName?: string
): Account {
  // 1. Authoritative lookup. Also means an email change at the provider keeps
  //    the same account rather than silently creating a second one.
  const bound = ctx.accounts.getByProviderIdentity(provider, providerAccountId);
  if (bound) return bound;

  // 2. No account for this provider identity. If the address already belongs to
  //    someone, it is not ours to take.
  const existing = ctx.accounts.getById(email);
  if (existing) {
    if (existing.provider || existing.provider_account_id) {
      // Owned by a different provider identity — step 1 would have matched.
      throw new AccountProviderMismatchError(email);
    }
    // Unbound pre-v6 row: adopt on first authenticated login. No such rows
    // exist in any deployed database; this only covers upgrade-in-place.
    ctx.accounts.bindProvider(email, provider, providerAccountId);
    return ctx.accounts.getById(email)!;
  }

  return ctx.accounts.create(email, displayName, provider, providerAccountId);
}

// ============================================================================
// Types
// ============================================================================

export interface OAuthConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}

export interface OAuthProviderConfig {
  google?: OAuthConfig;
  github?: OAuthConfig;
}

export interface OAuthTokenResponse {
  access_token: string;
  token_type: string;
  expires_in?: number;
  refresh_token?: string;
  scope?: string;
}

export interface OAuthUserInfo {
  id: string;
  email: string;
  name: string | null;
  avatar_url: string | null;
}

// ============================================================================
// Provider Endpoints
// ============================================================================

const GOOGLE_ENDPOINTS = {
  authorization: 'https://accounts.google.com/o/oauth2/v2/auth',
  token: 'https://oauth2.googleapis.com/token',
  userInfo: 'https://www.googleapis.com/oauth2/v2/userinfo',
};

const GITHUB_ENDPOINTS = {
  authorization: 'https://github.com/login/oauth/authorize',
  token: 'https://github.com/login/oauth/access_token',
  userInfo: 'https://api.github.com/user',
  // Authoritative verified-address list. The profile email from /user is
  // user-settable and unverified, so it must never decide account identity.
  userEmails: 'https://api.github.com/user/emails',
};

// ============================================================================
// Authorization URL Generation
// ============================================================================

export function getAuthorizationUrl(
  provider: 'google' | 'github',
  config: OAuthConfig,
  state: string
): string {
  const params = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    state,
    response_type: 'code',
  });
  
  if (provider === 'google') {
    params.set('scope', 'openid email profile');
    params.set('access_type', 'offline');
    params.set('prompt', 'consent');
    return `${GOOGLE_ENDPOINTS.authorization}?${params.toString()}`;
  }
  
  if (provider === 'github') {
    params.set('scope', 'read:user user:email');
    return `${GITHUB_ENDPOINTS.authorization}?${params.toString()}`;
  }
  
  throw new Error(`Unsupported provider: ${provider}`);
}

// ============================================================================
// Token Exchange
// ============================================================================

export async function exchangeCodeForToken(
  provider: 'google' | 'github',
  config: OAuthConfig,
  code: string
): Promise<OAuthTokenResponse> {
  const endpoints = provider === 'google' ? GOOGLE_ENDPOINTS : GITHUB_ENDPOINTS;
  
  const body: Record<string, string> = {
    code,
    client_id: config.clientId,
    client_secret: config.clientSecret,
    redirect_uri: config.redirectUri,
  };
  
  if (provider === 'google') {
    body.grant_type = 'authorization_code';
  }
  
  const response = await fetch(endpoints.token, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body: new URLSearchParams(body).toString(),
  });
  
  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Token exchange failed: ${error}`);
  }
  
  return response.json() as Promise<OAuthTokenResponse>;
}

// ============================================================================
// User Info Retrieval
// ============================================================================

export async function getUserInfo(
  provider: 'google' | 'github',
  accessToken: string
): Promise<OAuthUserInfo> {
  const endpoints = provider === 'google' ? GOOGLE_ENDPOINTS : GITHUB_ENDPOINTS;
  
  const response = await fetch(endpoints.userInfo, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: provider === 'github' ? 'application/vnd.github.v3+json' : 'application/json',
    },
  });
  
  if (!response.ok) {
    throw new Error(`Failed to get user info: ${response.statusText}`);
  }
  
  const data = await response.json() as any;

  if (provider === 'google') {
    return {
      id: String(data.id ?? data.sub),
      email: selectVerifiedEmail('google', data),
      name: data.name ?? null,
      avatar_url: data.picture ?? null,
    };
  }

  // GitHub's /user email field is the user's public profile string and is not
  // verified. /user/emails is the authoritative list; it needs the `user:email`
  // scope, which getAuthorizationUrl requests.
  const emailsResponse = await fetch(GITHUB_ENDPOINTS.userEmails, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/vnd.github.v3+json',
    },
  });

  if (!emailsResponse.ok) {
    throw new Error(
      `Failed to get verified GitHub emails: ${emailsResponse.statusText}. ` +
        `The user:email scope is required.`
    );
  }

  const emails = await emailsResponse.json() as Array<{
    email?: string;
    primary?: boolean;
    verified?: boolean;
  }>;

  return {
    id: String(data.id),
    email: selectVerifiedEmail('github', data, emails),
    name: data.name ?? data.login ?? null,
    avatar_url: data.avatar_url ?? null,
  };
}

// ============================================================================
// Token Hashing
// ============================================================================

/**
 * Hash a token for secure storage.
 * Uses HMAC-SHA256 with a server secret.
 */
export async function hashToken(
  token: string,
  serverSecret: string
): Promise<string> {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(serverSecret);
  const tokenData = encoder.encode(token);
  
  const key = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const signature = await crypto.subtle.sign('HMAC', key, tokenData);
  return Buffer.from(signature).toString('base64');
}

/**
 * Generate a random state parameter for OAuth.
 */
export function generateOAuthState(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Buffer.from(bytes).toString('base64url');
}
