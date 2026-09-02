// Custom Error Classes for FAM

// ============================================================================
// Base Error
// ============================================================================

export class FamError extends Error {
  public readonly code: string;
  public readonly statusCode: number;
  private _cause?: Error;

  constructor(message: string, code: string, statusCode: number = 500, cause?: Error) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
    this.statusCode = statusCode;
    this._cause = cause;
  }

  override get cause(): Error | undefined {
    return this._cause;
  }

  toJSON() {
    return {
      error: this.message,
      code: this.code,
    };
  }
}

// ============================================================================
// Specific Errors
// ============================================================================

export class NotFoundError extends FamError {
  constructor(resource: string, id: string) {
    super(`${resource} not found: ${id}`, 'NOT_FOUND', 404);
  }
}

export class UnauthorizedError extends FamError {
  constructor(message: string = 'Unauthorized') {
    super(message, 'UNAUTHORIZED', 401);
  }
}

export class ForbiddenError extends FamError {
  constructor(message: string = 'Forbidden') {
    super(message, 'FORBIDDEN', 403);
  }
}

export class ConflictError extends FamError {
  constructor(message: string) {
    super(message, 'CONFLICT', 409);
  }
}

/**
 * Refuses a `queue_empty = true` declaration that the queue contradicts.
 *
 * 409 rather than 400: the request is well-formed and would have been valid a
 * moment ago — it conflicts with current state, which is exactly what 409 is
 * for. A 400 would tell the caller to fix their request, and there is nothing
 * wrong with it.
 *
 * Carries the count, because "you have work pending" is actionable and "that
 * was rejected" is not.
 */
export class QueueNotEmptyError extends FamError {
  public readonly undelivered: number;

  constructor(entityId: string, undelivered: number) {
    super(
      `Cannot declare an empty queue for ${entityId}: ${undelivered} message(s) ` +
        'are waiting to be collected. Collect them, or declare queue_empty=false.',
      'QUEUE_NOT_EMPTY',
      409
    );
    this.undelivered = undelivered;
  }
}

export class ValidationError extends FamError {
  public readonly field?: string;

  constructor(message: string, field?: string) {
    super(message, 'VALIDATION_ERROR', 400);
    this.field = field;
  }

  override toJSON() {
    return {
      ...super.toJSON(),
      field: this.field,
    };
  }
}

export class ChallengeExpiredError extends FamError {
  constructor() {
    super('Challenge has expired', 'CHALLENGE_EXPIRED', 401);
  }
}

export class ChallengeMismatchError extends FamError {
  constructor() {
    super('Challenge nonce mismatch', 'CHALLENGE_MISMATCH', 401);
  }
}

export class SignatureInvalidError extends FamError {
  constructor() {
    super('Invalid signature', 'SIGNATURE_INVALID', 401);
  }
}

export class AccountExistsError extends FamError {
  constructor(email: string) {
    super(`Account already exists: ${email}`, 'ACCOUNT_EXISTS', 409);
  }
}

export class EntityExistsError extends FamError {
  constructor(entityId: string) {
    super(`Entity already exists: ${entityId}`, 'ENTITY_EXISTS', 409);
  }
}

export class EntityNotInChannelError extends FamError {
  constructor(entityId: string, channelId: string) {
    super(`Entity ${entityId} is not a member of channel ${channelId}`, 'ENTITY_NOT_IN_CHANNEL', 400);
  }
}

export class InsufficientCapabilitiesError extends FamError {
  constructor(capability: string) {
    super(`Entity lacks required capability: ${capability}`, 'INSUFFICIENT_CAPABILITIES', 403);
  }
}

export class DatabaseError extends FamError {
  constructor(message: string, originalError?: Error) {
    super(message, 'DATABASE_ERROR', 500, originalError);
  }
}

export class RequestEntityTooLargeError extends FamError {
  constructor(maxSize: number) {
    super(`Request body too large. Maximum size: ${maxSize} bytes`, 'REQUEST_TOO_LARGE', 413);
  }
}

/**
 * The provider identity presented does not own this account.
 *
 * Account ids are email addresses, so without provider binding anyone able to
 * present the same email string at ANY provider could claim the account.
 * Deliberately does not reveal which provider owns it.
 */
export class AccountProviderMismatchError extends FamError {
  constructor(accountId: string) {
    super(
      `Account ${accountId} is registered with a different identity provider. ` +
        `Sign in with the provider you originally used.`,
      'ACCOUNT_PROVIDER_MISMATCH',
      403
    );
  }
}

/**
 * The identity provider did not supply an address it has verified.
 */
export class UnverifiedEmailError extends FamError {
  constructor(provider: string) {
    super(
      `${provider} did not return a verified email address. FAM derives account ` +
        `identity from a verified address, so an unverified one cannot be used.`,
      'UNVERIFIED_EMAIL',
      403
    );
  }
}

/**
 * A stored message names a key the server no longer holds.
 *
 * Dropping a retired secret from the keyring is how encrypted data becomes
 * permanently unreadable, so this says exactly that rather than surfacing
 * AES-GCM's "operation failed for an operation-specific reason".
 */
export class MessageKeyUnavailableError extends FamError {
  constructor(keyId: string) {
    super(
      `Message was encrypted with key "${keyId}", which this server does not hold. ` +
        `Add the retired secret to FAM_SERVER_SECRET_PREVIOUS to read it.`,
      'MESSAGE_KEY_UNAVAILABLE',
      500
    );
  }
}

/**
 * Stored message data does not match the current FAM_ENCRYPT_MESSAGES setting.
 *
 * The flag is a boolean over a database that may already hold rows written
 * under the other setting, and neither direction fails usefully on its own:
 * turning it ON surfaces AES-GCM's "provided data is too small", and turning it
 * OFF is SILENT — the raw ciphertext envelope is handed back as message text.
 */
export class MessageEncryptionMismatchError extends FamError {
  constructor(detail: string) {
    super(detail, 'MESSAGE_ENCRYPTION_MISMATCH', 500);
  }
}

export class UnsupportedFormatVersionError extends FamError {
  constructor(formatName: string, found: string, maxSupported: string) {
    super(
      `${formatName} was written by a newer FAM version (${found}) than this server supports (${maxSupported}). Upgrade FAM to read it.`,
      'UNSUPPORTED_FORMAT_VERSION',
      500
    );
  }
}

/**
 * A sealed message could not be opened.
 *
 * Deliberately ONE error for "sealed to a different key" and "altered in
 * transit". The two are not distinguishable from the ciphertext, and a caller
 * who could tell them apart would hold an oracle for testing key ownership.
 */
export class SealedMessageError extends FamError {
  constructor(detail: string, cause?: Error) {
    super(detail, 'SEALED_MESSAGE_UNOPENABLE', 400, cause);
  }
}
