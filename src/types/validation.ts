// Input Validation Helpers for FAM

import { ValidationError } from './errors';

// ============================================================================
// Entity ID Validation
// ============================================================================

/**
 * Entity ID format: name@account
 * Name: alphanumeric, hyphens, underscores, dots (no @)
 * Account: email format
 */
const ENTITY_ID_REGEX = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9._@%+-]+$/;

/**
 * Validate entity ID format.
 */
export function validateEntityId(entityId: string): void {
  if (!ENTITY_ID_REGEX.test(entityId)) {
    throw new ValidationError(
      `Invalid entity ID format: ${entityId}. Expected format: name@account`,
      'entity_id'
    );
  }
  
  // Check length
  if (entityId.length > 254) {
    throw new ValidationError(
      'Entity ID too long (max 254 characters)',
      'entity_id'
    );
  }
}

// ============================================================================
// Account ID (Email) Validation
// ============================================================================

/**
 * Basic email validation.
 */
const EMAIL_REGEX = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

export function validateAccountId(accountId: string): void {
  if (!EMAIL_REGEX.test(accountId)) {
    throw new ValidationError(
      `Invalid account ID (email): ${accountId}`,
      'account_id'
    );
  }
  
  if (accountId.length > 254) {
    throw new ValidationError(
      'Account ID too long (max 254 characters)',
      'account_id'
    );
  }
}

// ============================================================================
// Channel ID Validation
// ============================================================================

/**
 * Channel ID should be a valid UUID.
 */
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function validateChannelId(channelId: string): void {
  if (!UUID_REGEX.test(channelId)) {
    throw new ValidationError(
      `Invalid channel ID (not a valid UUID): ${channelId}`,
      'channel_id'
    );
  }
}

// ============================================================================
// Entity Type Validation
// ============================================================================

const VALID_ENTITY_TYPES = ['agent', 'human', 'tool'] as const;

export function validateEntityType(type: string): void {
  if (!VALID_ENTITY_TYPES.includes(type as any)) {
    throw new ValidationError(
      `Invalid entity type: ${type}. Must be one of: ${VALID_ENTITY_TYPES.join(', ')}`,
      'type'
    );
  }
}

// ============================================================================
// Message Text Validation
// ============================================================================

const MAX_MESSAGE_LENGTH = 10000;

export function validateMessageText(text: string): void {
  if (!text || text.trim().length === 0) {
    throw new ValidationError('Message text cannot be empty', 'text');
  }
  
  if (text.length > MAX_MESSAGE_LENGTH) {
    throw new ValidationError(
      `Message too long (max ${MAX_MESSAGE_LENGTH} characters)`,
      'text'
    );
  }
}

// ============================================================================
// Channel Name Validation
// ============================================================================

const MAX_CHANNEL_NAME_LENGTH = 100;
const CHANNEL_NAME_REGEX = /^[a-zA-Z0-9._-]+$/;

export function validateChannelName(name: string): void {
  if (!name || name.trim().length === 0) {
    throw new ValidationError('Channel name cannot be empty', 'name');
  }
  
  if (name.length > MAX_CHANNEL_NAME_LENGTH) {
    throw new ValidationError(
      `Channel name too long (max ${MAX_CHANNEL_NAME_LENGTH} characters)`,
      'name'
    );
  }
  
  if (!CHANNEL_NAME_REGEX.test(name)) {
    throw new ValidationError(
      'Channel name can only contain alphanumeric characters, hyphens, underscores, and dots',
      'name'
    );
  }
}

// ============================================================================
// Pagination Validation
// ============================================================================

export interface PaginationParams {
  limit?: number;
  offset?: number;
}

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 100;

export function validatePagination(params: PaginationParams): { limit: number; offset: number } {
  const limit = params.limit ?? DEFAULT_LIMIT;
  const offset = params.offset ?? 0;
  
  if (limit < 1 || limit > MAX_LIMIT) {
    throw new ValidationError(
      `Limit must be between 1 and ${MAX_LIMIT}`,
      'limit'
    );
  }
  
  if (offset < 0) {
    throw new ValidationError('Offset must be non-negative', 'offset');
  }
  
  return { limit, offset };
}
