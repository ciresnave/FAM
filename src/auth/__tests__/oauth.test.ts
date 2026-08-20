import { test, expect, describe } from 'bun:test';
import { selectVerifiedEmail, resolveAccountForProvider } from '../oauth';
import { getDatabaseContext } from '../../db';

// ============================================================================
// Verified email selection
//
// The account id is derived from the provider's email, so an email the
// provider has not verified is an attacker-controlled string. GitHub's
// /user endpoint returns the user's PUBLIC PROFILE email, which the user
// sets freely and GitHub never verifies.
// ============================================================================

describe('selectVerifiedEmail', () => {
  test('returns the Google email when Google reports it verified', () => {
    const email = selectVerifiedEmail('google', {
      id: '1',
      email: 'alice@gmail.com',
      email_verified: true,
    });
    expect(email).toBe('alice@gmail.com');
  });

  test('rejects a Google profile whose email is not verified', () => {
    expect(() =>
      selectVerifiedEmail('google', {
        id: '1',
        email: 'victim@gmail.com',
        email_verified: false,
      })
    ).toThrow();
  });

  test("returns GitHub's primary verified address from /user/emails", () => {
    const email = selectVerifiedEmail(
      'github',
      { id: 7, login: 'alice', email: 'anything-i-typed@gmail.com' },
      [
        { email: 'other@example.com', primary: false, verified: true },
        { email: 'alice@real.com', primary: true, verified: true },
      ]
    );
    expect(email).toBe('alice@real.com');
  });

  test('ignores the unverified GitHub profile email entirely', () => {
    // The profile email is attacker-set; only /user/emails is authoritative.
    const email = selectVerifiedEmail(
      'github',
      { id: 7, login: 'mallory', email: 'victim@gmail.com' },
      [{ email: 'mallory@real.com', primary: true, verified: true }]
    );
    expect(email).toBe('mallory@real.com');
  });

  test('rejects a GitHub account with no verified address', () => {
    expect(() =>
      selectVerifiedEmail(
        'github',
        { id: 7, login: 'mallory', email: 'victim@gmail.com' },
        [{ email: 'mallory@real.com', primary: true, verified: false }]
      )
    ).toThrow();
  });

  test('never synthesises an address from the GitHub login', () => {
    expect(() =>
      selectVerifiedEmail('github', { id: 7, login: 'mallory', email: null }, [])
    ).toThrow();
  });
});

// ============================================================================
// Provider binding
//
// An account is bound to the provider identity that created it. Matching on
// email alone lets anyone who can present the same email string at ANY
// provider claim the account.
// ============================================================================

describe('resolveAccountForProvider', () => {
  test('creates and binds a new account on first login', () => {
    const ctx = getDatabaseContext();
    const account = resolveAccountForProvider(ctx, 'google', 'g-100', 'new-user@bind.test', 'New User');

    expect(account.id).toBe('new-user@bind.test');
    const row = ctx.db
      .prepare('SELECT provider, provider_account_id FROM accounts WHERE id = ?')
      .get('new-user@bind.test') as { provider: string; provider_account_id: string };
    expect(row.provider).toBe('google');
    expect(row.provider_account_id).toBe('g-100');
  });

  test('returns the same account when the same provider identity logs in again', () => {
    const ctx = getDatabaseContext();
    resolveAccountForProvider(ctx, 'google', 'g-200', 'repeat@bind.test', 'Repeat');
    const again = resolveAccountForProvider(ctx, 'google', 'g-200', 'repeat@bind.test', 'Repeat');

    expect(again.id).toBe('repeat@bind.test');
  });

  // THE VULNERABILITY: GitHub profile emails are unverified and user-settable,
  // so without provider binding, setting a GitHub profile email to a victim's
  // Google address hands over their account.
  test('rejects a login from a different provider for an existing account', () => {
    const ctx = getDatabaseContext();
    resolveAccountForProvider(ctx, 'google', 'g-300', 'victim@bind.test', 'Victim');

    expect(() =>
      resolveAccountForProvider(ctx, 'github', 'gh-999', 'victim@bind.test', 'Mallory')
    ).toThrow();
  });

  test('rejects a login from the same provider but a different provider account id', () => {
    const ctx = getDatabaseContext();
    resolveAccountForProvider(ctx, 'github', 'gh-400', 'shared@bind.test', 'Owner');

    expect(() =>
      resolveAccountForProvider(ctx, 'github', 'gh-401', 'shared@bind.test', 'Impostor')
    ).toThrow();
  });
});
