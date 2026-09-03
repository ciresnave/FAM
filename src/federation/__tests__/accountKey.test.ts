import { test, expect, describe } from 'bun:test';
import {
  accountKeyUrl,
  fetchAccountKey,
  type Fetcher,
} from '../accountKey';

// ============================================================================
// Fetching an account key from the holder's own forge repository.
//
// This is where the anchor stops being a design claim. Everything else in the
// voucher chain takes the account public key as a parameter and refuses to say
// where it came from — deliberately, because the only source FAM knows is the
// relay, which is the party being defended against. This module is the answer
// to "then where DOES it come from".
//
// ⚠️ AND IT IS THE ONE PLACE IN FAM WHERE SSRF IS A REAL CONCERN RATHER THAN A
// LINTER'S GUESS. A function that fetches a URL derived from user input is
// exactly the shape those rules exist for — so this one CANNOT EXPRESS AN
// ARBITRARY URL. The host is fixed per forge, the path is a template, and the
// only variable is a username validated against the forge's own rules.
//
// Same structural form as `/entities/encryption-key` accepting a public key
// only: not "we check that the URL is safe", but "there is no code path by
// which an unsafe one is constructed".
// ============================================================================

const GITHUB = { forge: 'github' as const, username: 'ciresnave' };

function fetcherReturning(body: string, ok = true, status = 200): Fetcher {
  return async () => ({ ok, status, text: async () => body });
}

/** A well-formed base64 Ed25519 public key. */
const KEY = Buffer.alloc(32, 3).toString('base64');

describe('the URL is DERIVED, never accepted', () => {
  test('it points at the holder-controlled path on a fixed host', () => {
    const url = accountKeyUrl(GITHUB);
    expect(url).toStartWith('https://raw.githubusercontent.com/');
    expect(url).toContain('/ciresnave/ciresnave/');
    expect(url).toEndWith('/fam/account.pub');
  });

  test('⚠️ a username that tries to escape the template is REFUSED', () => {
    // The whole SSRF surface, and it is closed by validation rather than by
    // sanitising — a rejected username cannot produce a URL at all, so there is
    // no "cleaned" value to get wrong.
    const attacks = [
      '../../evil',
      'user/../../..',
      'evil.com',
      'user@evil.com',
      'https://evil.com',
      'user?x=1',
      'user#frag',
      'user%2f..',
      '',
      'a'.repeat(40), // GitHub caps usernames at 39
      'user name',
      '.leading-dot',
      '-leading-hyphen',
    ];

    for (const username of attacks) {
      expect(() => accountKeyUrl({ forge: 'github', username })).toThrow();
    }
  });

  test('a legitimate username is accepted, so the guard is not just "refuse everything"', () => {
    // The positive control. Without it every assertion above is satisfied by a
    // function that throws unconditionally.
    for (const username of ['ciresnave', 'a', 'a-b', 'user123', 'a'.repeat(39)]) {
      expect(() => accountKeyUrl({ forge: 'github', username })).not.toThrow();
    }
  });

  test('an unknown forge is refused rather than defaulted', () => {
    // A default forge would mean a typo silently fetches from the wrong host —
    // and the wrong host is an attacker-chosen one if the typo is chosen.
    expect(() => accountKeyUrl({ forge: 'gitlob' as any, username: 'ciresnave' })).toThrow(
      /forge/i
    );
  });
});

describe('fetching', () => {
  test('a well-formed key comes back with the URL it came from', async () => {
    const result = await fetchAccountKey(GITHUB, fetcherReturning(KEY));
    expect(result.publicKey).toBe(KEY);
    expect(result.url).toBe(accountKeyUrl(GITHUB));
  });

  test('surrounding whitespace and a trailing newline are tolerated', async () => {
    // A file written by a human through a web editor almost always ends in a
    // newline. Refusing that would make the common case fail for a reason the
    // holder cannot see.
    const result = await fetchAccountKey(GITHUB, fetcherReturning(`  ${KEY}\n`));
    expect(result.publicKey).toBe(KEY);
  });

  test('a non-OK response is an error, not an empty key', async () => {
    // ⚠️ A 404 must not read as "this holder has no key". An absent file and a
    // failed request are different facts, and treating a fetch failure as a
    // key-shaped absence is how a peer ends up trusting nothing when it should
    // be alarmed — or worse, falling back to the relay's copy.
    await expect(fetchAccountKey(GITHUB, fetcherReturning('', false, 404))).rejects.toThrow(
      /404/
    );
  });

  test('a body that is not a key is refused', async () => {
    await expect(
      fetchAccountKey(GITHUB, fetcherReturning('<!DOCTYPE html><html>404</html>'))
    ).rejects.toThrow();
  });

  test('a key of the wrong length is refused', async () => {
    await expect(
      fetchAccountKey(GITHUB, fetcherReturning(Buffer.alloc(16, 3).toString('base64')))
    ).rejects.toThrow(/32 bytes/);
  });

  test('⚠️ the fetcher is only ever called with the derived URL', async () => {
    // The structural assertion. A module that derived a safe URL and then
    // fetched something else would pass every test above.
    const seen: string[] = [];
    const spy: Fetcher = async (url) => {
      seen.push(url);
      return { ok: true, status: 200, text: async () => KEY };
    };

    await fetchAccountKey(GITHUB, spy);
    expect(seen).toEqual([accountKeyUrl(GITHUB)]);
  });
});
