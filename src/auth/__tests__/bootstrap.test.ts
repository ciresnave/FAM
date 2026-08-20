import { test, expect, describe } from 'bun:test';
import { bootstrapAccount } from '../bootstrap';
import { resolveAccountForProvider } from '../oauth';
import { validateAccountToken } from '../../server/middleware/auth';
import { getDatabaseContext } from '../../db';

const SECRET = process.env.FAM_SERVER_SECRET!;

// ============================================================================
// Local bootstrap
//
// Without this, the OAuth callback is the only path that creates an account,
// so a fresh clone cannot be run at all without registering a Google or GitHub
// OAuth application. This is the difference between FAM being inspectable and
// FAM being runnable.
// ============================================================================

describe('bootstrapAccount', () => {
  test('creates an account and issues a token that authenticates', async () => {
    const ctx = getDatabaseContext();
    const { account_id, token } = await bootstrapAccount(ctx, 'boot-one@local.test', SECRET);

    expect(account_id).toBe('boot-one@local.test');
    expect(token).toBeTruthy();

    // The token must work against the real validator, not just exist.
    const resolved = await validateAccountToken(ctx, token);
    expect(resolved).toBe('boot-one@local.test');
  });

  test('rejects a malformed email', async () => {
    const ctx = getDatabaseContext();
    await expect(bootstrapAccount(ctx, 'not-an-email', SECRET)).rejects.toThrow();
  });

  test('re-issues a token for an existing local account', async () => {
    const ctx = getDatabaseContext();
    const first = await bootstrapAccount(ctx, 'boot-again@local.test', SECRET);
    const second = await bootstrapAccount(ctx, 'boot-again@local.test', SECRET);

    expect(second.account_id).toBe(first.account_id);
    expect(second.token).not.toBe(first.token);
    // The newly issued token authenticates.
    expect(await validateAccountToken(ctx, second.token)).toBe('boot-again@local.test');
  });

  test('refuses to issue a token for an account owned by an OAuth provider', async () => {
    const ctx = getDatabaseContext();
    resolveAccountForProvider(ctx, 'google', 'g-boot-1', 'boot-oauth@local.test', 'Owner');

    // Bootstrapping over an OAuth-owned account would hand out a credential for
    // somebody else's identity to anyone with filesystem access to the DB.
    await expect(bootstrapAccount(ctx, 'boot-oauth@local.test', SECRET)).rejects.toThrow();
  });

  // THE SECURITY PROPERTY: a locally bootstrapped account has no provider
  // binding, so it must not be claimable by the first OAuth login that presents
  // the same address.
  test('a bootstrapped account cannot be claimed by an OAuth login', async () => {
    const ctx = getDatabaseContext();
    await bootstrapAccount(ctx, 'boot-claim@local.test', SECRET);

    expect(() =>
      resolveAccountForProvider(ctx, 'github', 'gh-claim-1', 'boot-claim@local.test', 'Mallory')
    ).toThrow();
  });
});
