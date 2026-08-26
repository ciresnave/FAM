import { test, expect, describe } from 'bun:test';
import { FamHttpError, isPermanentFailure, reconnectDelay } from '../client';

// ============================================================================
// Reconnect classification
//
// attemptReconnect() caught every failure identically and retried. A deleted
// entity (404) and a revoked one (401) are PERMANENT — no amount of retrying
// fixes them — but they were retried on the same schedule as a network blip.
//
// Correcting my own earlier description: this is not a hot loop. Backoff is
// exponential and attempts are capped at 10, so it self-limits. What it
// actually costs is ~17 minutes of pointless re-authentication against the
// server, during which the agent is unusable and nothing says why — and then a
// silent give-up that only reaches a console.
// ============================================================================

describe('failure classification', () => {
  test('an HTTP error carries its status', () => {
    const e = new FamHttpError('/entities/connect', 404, 'Entity not found');
    expect(e.status).toBe(404);
    expect(e.message).toContain('404');
    expect(e.message).toContain('/entities/connect');
  });

  // These cannot be fixed by waiting: the entity is gone, or this key is no
  // longer allowed to speak for it.
  test('404, 401 and 403 are permanent', () => {
    for (const status of [401, 403, 404]) {
      expect(isPermanentFailure(new FamHttpError('/x', status, 'nope'))).toBe(true);
    }
  });

  test('server errors are transient — the entity may still be fine', () => {
    for (const status of [500, 502, 503, 504]) {
      expect(isPermanentFailure(new FamHttpError('/x', status, 'oops'))).toBe(false);
    }
  });

  test('rate limiting is transient', () => {
    expect(isPermanentFailure(new FamHttpError('/x', 429, 'slow down'))).toBe(false);
  });

  // A dropped connection is the case reconnection exists for.
  test('network errors are transient', () => {
    expect(isPermanentFailure(new TypeError('fetch failed'))).toBe(false);
    expect(isPermanentFailure(new Error('ECONNREFUSED'))).toBe(false);
    expect(isPermanentFailure(undefined)).toBe(false);
  });
});

describe('backoff', () => {
  test('grows with the attempt count', () => {
    expect(reconnectDelay(1)).toBeGreaterThan(reconnectDelay(0));
    expect(reconnectDelay(3)).toBeGreaterThan(reconnectDelay(2));
  });

  // Uncapped doubling reaches 512s by attempt 10, so the last few retries are
  // minutes apart — long enough that a recovered server goes unnoticed.
  test('is capped so late attempts stay useful', () => {
    for (const attempt of [8, 9, 10, 20]) {
      expect(reconnectDelay(attempt)).toBeLessThanOrEqual(30_000);
    }
  });

  test('starts small so a brief blip recovers quickly', () => {
    expect(reconnectDelay(0)).toBeLessThanOrEqual(2_000);
  });
});
