// Fetching an account key from the holder's own forge repository.
//
// ─────────────────────────────────────────────────────────────────────────────
// THIS IS WHERE THE ANCHOR STOPS BEING A DESIGN CLAIM.
//
// Everything else in the voucher chain takes the account public key as a
// parameter and refuses to say where it came from — deliberately, because the
// only source FAM knows is the relay, and the relay is the party being defended
// against. This module is the answer to "then where DOES it come from": the
// account holder's own repository, which the relay cannot write to.
// ─────────────────────────────────────────────────────────────────────────────
//
// ⚠️ AND IT IS THE ONE PLACE IN FAM WHERE SSRF IS A REAL CONCERN RATHER THAN A
// LINTER'S GUESS — a function that fetches a URL derived from user input is
// exactly the shape those rules exist for.
//
// So this one CANNOT EXPRESS AN ARBITRARY URL. The host is a fixed constant per
// forge, the path is a template, and the only variable is a username validated
// against that forge's own naming rules before it is substituted. There is no
// parameter that accepts a URL, and no code path that builds one from anything
// but the template.
//
// Same structural form as `/entities/encryption-key` accepting a public key
// only: not "we check that the URL is safe", but "there is no code path by
// which an unsafe one is constructed". A validated input beats a sanitised one
// because a rejected username produces NO url, so there is no cleaned value
// left to get wrong.

import { ValidationError } from '../types/errors';
import { assertRaw32ByteKey } from '../types/validation';

export type Forge = 'github';

export interface AnchorLocation {
  forge: Forge;
  /** The holder's username on that forge. Validated, never interpolated raw. */
  username: string;
}

/**
 * Minimal shape of `fetch`, injected.
 *
 * A parameter rather than a direct call so tests never touch the network — and
 * so a caller can supply one with its own timeout and redirect policy. A module
 * that reached for the global would be untestable and unbounded.
 */
export type Fetcher = (
  url: string
) => Promise<{ ok: boolean; status: number; text: () => Promise<string> }>;

export interface FetchedAccountKey {
  publicKey: string;
  /** Recorded so a caller can show WHERE a key came from, not just what it is. */
  url: string;
}

/**
 * Per-forge templates. Host is a constant; the username is the only variable.
 *
 * GitHub serves a user's self-named repository at `<user>/<user>`, which is the
 * one repo a holder unambiguously controls and which peers can find knowing
 * only the username.
 */
const FORGES: Record<Forge, { template: (username: string) => string; valid: RegExp }> = {
  github: {
    template: (u) => `https://raw.githubusercontent.com/${u}/${u}/main/fam/account.pub`,
    // GitHub's own rule: alphanumeric or single hyphens, cannot begin or end
    // with a hyphen, 39 characters max. Anchored at both ends — an unanchored
    // pattern would match a valid username sitting inside a hostile string.
    valid: /^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$/,
  },
};

/**
 * The canonical URL for a holder's account key.
 *
 * Throws rather than returning a sanitised value: a rejected username must
 * produce no URL at all, so there is nothing half-cleaned for a caller to use.
 */
export function accountKeyUrl(location: AnchorLocation): string {
  const forge = FORGES[location.forge];
  if (!forge) {
    // Refused rather than defaulted. A default forge means a typo silently
    // fetches from the wrong host — and the wrong host is attacker-chosen if
    // the typo is.
    throw new ValidationError(
      `Unknown forge "${location.forge}". Known: ${Object.keys(FORGES).join(', ')}.`
    );
  }

  if (typeof location.username !== 'string' || !forge.valid.test(location.username)) {
    throw new ValidationError(
      `"${location.username}" is not a valid ${location.forge} username, so no account-key URL can be built for it.`
    );
  }

  return forge.template(location.username);
}

/**
 * Fetch and validate the account public key at a holder's anchor.
 *
 * ⚠️ A FAILED REQUEST IS AN ERROR, NEVER AN ABSENT KEY. A 404 must not read as
 * "this holder has no key": an absent file and a failed request are different
 * facts, and collapsing them is how a peer ends up either alarmed for no reason
 * or — far worse — falling back to the relay's copy because "the anchor had
 * nothing".
 */
export async function fetchAccountKey(
  location: AnchorLocation,
  fetcher: Fetcher
): Promise<FetchedAccountKey> {
  const url = accountKeyUrl(location);

  const response = await fetcher(url);
  if (!response.ok) {
    throw new ValidationError(
      `Fetching the account key at ${url} failed with status ${response.status}.`
    );
  }

  // Trimmed because a file written through a web editor almost always ends in a
  // newline, and refusing that would make the common case fail for a reason the
  // holder cannot see from their end.
  const body = (await response.text()).trim();

  // One shared validator rather than a fourth copy of the same rule. The
  // round-trip comparison matters here more than anywhere: an HTML error page
  // decodes to something, and a long enough one decodes to 32 bytes.
  assertRaw32ByteKey(body, {
    field: `The account key at ${url}`,
    why: 'A key file should contain only the key.',
  });

  return { publicKey: body, url };
}
