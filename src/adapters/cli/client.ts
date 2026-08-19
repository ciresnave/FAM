// HTTP Client for CLI Commands

import type { CliConfig } from './config';
import { getServerUrl, getAccountToken, getActiveEntityId } from './config';

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

/**
 * Make an authenticated request with entity context.
 */
export async function entityRequest<T>(
  config: CliConfig,
  path: string,
  extraBody?: object
): Promise<T> {
  const entityId = await getActiveEntityId(config);
  
  return apiRequest<T>(config, path, {
    entity_id: entityId,
    ...extraBody,
  });
}
