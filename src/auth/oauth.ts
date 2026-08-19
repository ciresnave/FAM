// OAuth 2.0 Handlers for Account Authentication
//
// Supports Google and GitHub as identity providers.

import { hashSha256 } from '../crypto/keys';

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
      id: data.id,
      email: data.email,
      name: data.name,
      avatar_url: data.picture,
    };
  }
  
  // GitHub
  return {
    id: String(data.id),
    email: data.email || `${data.login}@github.com`,
    name: data.name || data.login,
    avatar_url: data.avatar_url,
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
