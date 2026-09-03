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


/**
 * Refuse an over-long field, in the unit the message actually reports.
 *
 * ONE implementation because there were four, and they disagreed. Two counted
 * bytes and said bytes; one counted CHARACTERS and said BYTES — so a multibyte
 * value passed a bound it exceeded, wrong in the permissive direction, which is
 * the direction that does not announce itself. That defect was found and fixed
 * in one copy during review and left standing in another, which is what having
 * copies means.
 *
 * The unit is a REQUIRED argument rather than a default, so a call site has to
 * say which it means and the message matches by construction. Both units are
 * legitimate: a storage bound is bytes, a readability bound ("a sentence or
 * two") is characters, and picking one globally would make one of them lie.
 *
 * Refused, never truncated — a cut-off value is a claim nobody wrote.
 */
export function assertWithinLimit(
  value: string,
  limit: number,
  opts: { unit: 'bytes' | 'characters'; field: string; why: string }
): void {
  const size =
    opts.unit === 'bytes' ? new TextEncoder().encode(value).byteLength : value.length;

  if (size > limit) {
    throw new ValidationError(
      `${opts.field} is ${size} ${opts.unit}; the limit is ${limit} ${opts.unit}. ` +
        `Refused rather than truncated — ${opts.why}`
    );
  }
}

/**
 * Assert that `value` is base64 encoding exactly 32 raw bytes — the size of an
 * Ed25519 or X25519 key.
 *
 * ⚠️ EXTRACTED BECAUSE THERE WERE THREE COPIES AND A FOURTH WAS ABOUT TO BE
 * WRITTEN. Entity encryption keys, `/accounts/create-entity`'s identity key and
 * the forge-repo account key each had their own, and account-key pinning needed
 * the same check again.
 *
 * That is the shape flagged on the voucher routes an hour earlier: three copies
 * of one rule agreeing by coincidence of authorship rather than by
 * construction. Here the copies were still identical — which is exactly when
 * collapsing them is cheap, and after they diverge is when it is not.
 *
 * ⚠️ THE ROUND-TRIP COMPARISON IS NOT DECORATION. `Buffer.from(x, 'base64')`
 * SKIPS characters outside the alphabet rather than throwing, so an HTML error
 * page or a string with punctuation spliced in decodes to something short
 * instead of failing — and a long enough one decodes to exactly 32 bytes and
 * passes a length check alone. Re-encoding and comparing is what actually
 * detects it.
 */
export function assertRaw32ByteKey(
  value: unknown,
  context: { field: string; why?: string }
): asserts value is string {
  const suffix = context.why ? ` ${context.why}` : '';

  if (typeof value !== 'string' || value === '') {
    throw new ValidationError(`${context.field} is required and must be a base64 string.${suffix}`);
  }

  const decoded = Buffer.from(value, 'base64');

  if (decoded.toString('base64').replace(/=+$/, '') !== value.replace(/=+$/, '')) {
    throw new ValidationError(`${context.field} must be valid base64.${suffix}`);
  }

  if (decoded.length !== 32) {
    throw new ValidationError(
      `${context.field} must be 32 bytes when decoded; got ${decoded.length}.${suffix}`
    );
  }
}
