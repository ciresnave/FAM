// The out-of-band fingerprint of an account key.
//
// ─────────────────────────────────────────────────────────────────────────────
// ⚠️ THIS IS WHAT MAKES AN ANCHOR CHECKABLE RATHER THAN MERELY RELAY-INDEPENDENT.
//
// `DESIGN-FEDERATION.md`: "The anchor is currently REAL BUT NOT VERIFIABLE …
// A peer that fetches an account key from a repo has removed the RELAY from the
// trust path — but cannot tell that the key it holds CAME from there, nor
// notice when the answer changes. Closing that needs pinning-on-first-use with
// change alerts, a transparency log, or at minimum a fingerprint the holder
// publishes out of band."
//
// Pinning with change alerts shipped. This is the fingerprint. Together they
// convert TRUST-on-first-use into VERIFIED-on-first-use: a peer told the
// fingerprint by some channel the relay does not control can check that the key
// a forge served is the one the holder meant.
// ─────────────────────────────────────────────────────────────────────────────
//
// ⚠️ NOT THE SAME CONCEPT AS `keyIdFor` IN `message-encryption.ts`, which
// fingerprints the SERVER SECRET so a stored row can say which key sealed it.
// Same word, unrelated subject, and this codebase already insists on saying
// under whose key. Say which fingerprint.

import { assertRaw32ByteKey } from '../types/validation';

/** Bytes of SHA-256 kept. 16 = 128 bits. */
const FINGERPRINT_BYTES = 16;

/**
 * A short, stable, human-comparable fingerprint of an account public key.
 *
 * ⚠️ COMPUTED OVER THE RAW KEY BYTES, NEVER THE BASE64 TEXT. A fingerprint that
 * depended on the encoding would differ between two spellings of one key, and
 * would do so exactly when somebody re-encodes a key while moving it between
 * systems — the moment they most need it to hold.
 *
 * ⚠️ AND IT REFUSES A KEY IT CANNOT PARSE. A fingerprint of a malformed key is
 * a confident answer about nothing: it would be compared against a real one,
 * reported as a mismatch, and send a person to investigate a substitution when
 * the actual fault was a truncated paste.
 *
 * FORMAT: 128 bits as eight hyphen-separated groups of four hex digits. Hex
 * because a person reads this aloud to another person — no I/l or O/0 to
 * confuse, and no new encoder to implement incorrectly. 128 bits because the
 * attack is grinding a key whose fingerprint matches a published one, and that
 * is infeasible at this width while still fitting in a phone call.
 */
export async function accountKeyFingerprint(publicKeyBase64: string): Promise<string> {
  assertRaw32ByteKey(publicKeyBase64, {
    field: 'The account key to fingerprint',
    why: 'A fingerprint of something that is not a key would still look like a fingerprint.',
  });

  const raw = Uint8Array.from(Buffer.from(publicKeyBase64, 'base64'));
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', raw));

  const hex = Array.from(digest.slice(0, FINGERPRINT_BYTES))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  return (hex.match(/.{4}/g) ?? []).join('-');
}

/**
 * Compare a fingerprint a person was told against one computed from a key.
 *
 * ⚠️ NORMALISED BEFORE COMPARING, because the holder reads it aloud and the
 * peer types it. Case and separators are presentation; the digits are the
 * claim. Refusing `A1B2C3D4…` because it was not lowercased would train people
 * to stop checking, which costs more than it protects.
 *
 * ⚠️ BUT NOTHING ELSE IS FORGIVEN. A fingerprint that is merely a PREFIX of the
 * real one does not match: accepting prefixes would let an attacker grind a
 * much shorter target, and the whole width is the security parameter.
 */
export function fingerprintsMatch(told: string, computed: string): boolean {
  const normalise = (s: string) => s.replace(/[\s-]/g, '').toLowerCase();
  return normalise(told) === normalise(computed);
}
