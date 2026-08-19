import { test, expect, describe } from 'bun:test';
import {
  validateEntityId,
  validateAccountId,
  validateChannelId,
  validateEntityType,
  validateMessageText,
  validateChannelName,
  validatePagination,
} from '../validation';
import { ValidationError } from '../errors';

describe('Entity ID Validation', () => {
  test('valid entity ID', () => {
    expect(() => validateEntityId('user@example.com')).not.toThrow();
    expect(() => validateEntityId('agent@company.com')).not.toThrow();
    expect(() => validateEntityId('tool@local')).not.toThrow();
  });

  test('invalid entity ID', () => {
    expect(() => validateEntityId('')).toThrow(ValidationError);
    expect(() => validateEntityId('invalid')).toThrow(ValidationError);
    expect(() => validateEntityId('no-at-sign')).toThrow(ValidationError);
    expect(() => validateEntityId('@no-name.com')).toThrow(ValidationError);
    expect(() => validateEntityId('name@')).toThrow(ValidationError);
  });
});

describe('Account ID Validation', () => {
  test('valid account ID', () => {
    expect(() => validateAccountId('user@example.com')).not.toThrow();
    expect(() => validateAccountId('user.name@example.com')).not.toThrow();
  });

  test('invalid account ID', () => {
    expect(() => validateAccountId('')).toThrow(ValidationError);
    expect(() => validateAccountId('invalid')).toThrow(ValidationError);
  });
});

describe('Channel ID Validation', () => {
  test('valid channel ID (UUID)', () => {
    expect(() => validateChannelId('550e8400-e29b-41d4-a716-446655440000')).not.toThrow();
    expect(() => validateChannelId('6ba7b810-9dad-11d1-80b4-00c04fd430c8')).not.toThrow();
  });

  test('invalid channel ID', () => {
    expect(() => validateChannelId('')).toThrow(ValidationError);
    expect(() => validateChannelId('not-a-uuid')).toThrow(ValidationError);
    expect(() => validateChannelId('general')).toThrow(ValidationError);
  });
});

describe('Entity Type Validation', () => {
  test('valid entity types', () => {
    expect(() => validateEntityType('agent')).not.toThrow();
    expect(() => validateEntityType('human')).not.toThrow();
    expect(() => validateEntityType('tool')).not.toThrow();
  });

  test('invalid entity type', () => {
    expect(() => validateEntityType('invalid')).toThrow(ValidationError);
    expect(() => validateEntityType('')).toThrow(ValidationError);
  });
});

describe('Message Text Validation', () => {
  test('valid message text', () => {
    expect(() => validateMessageText('Hello, world!')).not.toThrow();
    expect(() => validateMessageText('Test message 123')).not.toThrow();
  });

  test('invalid message text', () => {
    expect(() => validateMessageText('')).toThrow(ValidationError);
    expect(() => validateMessageText('   ')).toThrow(ValidationError);
  });
});

describe('Channel Name Validation', () => {
  test('valid channel name', () => {
    expect(() => validateChannelName('general')).not.toThrow();
    expect(() => validateChannelName('my-channel')).not.toThrow();
    expect(() => validateChannelName('channel_123')).not.toThrow();
  });

  test('invalid channel name', () => {
    expect(() => validateChannelName('')).toThrow(ValidationError);
    expect(() => validateChannelName('has spaces')).toThrow(ValidationError);
    expect(() => validateChannelName('has@special')).toThrow(ValidationError);
  });
});

describe('Pagination Validation', () => {
  test('valid pagination', () => {
    expect(validatePagination({ limit: 10, offset: 0 })).toEqual({ limit: 10, offset: 0 });
    expect(validatePagination({ limit: 50, offset: 100 })).toEqual({ limit: 50, offset: 100 });
  });

  test('invalid pagination', () => {
    expect(() => validatePagination({ limit: -1, offset: 0 })).toThrow(ValidationError);
    expect(() => validatePagination({ limit: 101, offset: 0 })).toThrow(ValidationError);
    expect(() => validatePagination({ limit: 10, offset: -1 })).toThrow(ValidationError);
  });
});
