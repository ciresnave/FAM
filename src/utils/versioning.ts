// Format Versioning for FAM
//
// Every persisted or wire format (EncryptedKeyFile, message ciphertext envelope,
// credentials.json, WebSocket envelope) carries a `version` field equal to the
// FAM semantic version that produced it. Formats therefore version alongside
// the code.
//
// Compatibility contract:
// - Producers stamp `version` with the current FAM_VERSION.
// - Consumers accept:
//     * absent version  → legacy format (pre-versioning), assumed compatible
//     * version <= FAM_VERSION (semver compare) → compatible
//     * version >  FAM_VERSION → reject (written by a newer FAM; refuse to
//       guess at the format rather than corrupt data)

import pkg from '../../package.json';
import { UnsupportedFormatVersionError } from '../types/errors';

// ============================================================================
// Constants
// ============================================================================

export const FAM_VERSION: string = pkg.version;

// ============================================================================
// Semver Comparison
// ============================================================================

/**
 * Compare two semantic version strings.
 * Returns negative if a < b, 0 if equal, positive if a > b.
 * Pre-release suffixes (e.g. "1.2.3-beta") sort before the release.
 */
export function compareSemver(a: string, b: string): number {
  const parse = (v: string) => {
    const [core, prerelease] = v.split('-', 2);
    const parts = core.split('.').map(n => parseInt(n, 10) || 0);
    return { parts, prerelease };
  };

  const pa = parse(a);
  const pb = parse(b);

  for (let i = 0; i < 3; i++) {
    const na = pa.parts[i] ?? 0;
    const nb = pb.parts[i] ?? 0;
    if (na !== nb) return na - nb;
  }

  // Equal cores: release > pre-release
  if (!pa.prerelease && !pb.prerelease) return 0;
  if (!pa.prerelease) return 1;
  if (!pb.prerelease) return -1;
  return pa.prerelease.localeCompare(pb.prerelease);
}

/**
 * Does this string actually look like a semantic version?
 *
 * compareSemver() is deliberately lenient — it uses `parseInt(n) || 0`, so
 * "not-a-version" parses as 0.0.0 and compares as OLDER than everything. That
 * is fine for ordering two versions FAM produced, and wrong for validating one
 * a client supplied: garbage would be accepted as ancient rather than refused.
 */
export function isValidSemver(version: string): boolean {
  return /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(version);
}

/**
 * Can this server talk to a client declaring `version`?
 *
 * - absent  -> yes. The versioning contract treats a missing version as
 *              predating versioning, and those clients are compatible.
 * - older / equal -> yes.
 * - newer   -> no. A newer client may send frames this server cannot parse;
 *              refusing at connect beats failing frame by frame afterwards.
 * - malformed -> no. Not silently treated as 0.0.0.
 */
export function isClientVersionSupported(
  version: string | null | undefined,
  maxVersion: string = FAM_VERSION
): boolean {
  if (version === null || version === undefined || version === '') return true;
  if (!isValidSemver(version)) return false;
  return compareSemver(version, maxVersion) <= 0;
}

// ============================================================================
// Stamp & Validate
// ============================================================================

/**
 * A format object carrying a version field.
 */
export interface Versioned {
  version?: string;
}

/**
 * Stamp a format object with the current FAM version.
 * Returns a shallow copy; the input is not mutated.
 */
export function stampVersion<T extends object>(obj: T): T & { version: string } {
  return { ...obj, version: FAM_VERSION };
}

/**
 * Extract a version from a parsed format object.
 * Returns undefined for legacy (unversioned) formats.
 */
export function readVersion(obj: Versioned): string | undefined {
  return typeof obj.version === 'string' ? obj.version : undefined;
}

/**
 * Validate a format object's version against the running FAM version.
 * Returns true when the format is compatible (legacy, equal, or older).
 */
export function isFormatSupported(obj: Versioned, maxVersion: string = FAM_VERSION): boolean {
  const version = readVersion(obj);
  if (version === undefined) return true; // legacy format
  return compareSemver(version, maxVersion) <= 0;
}

/**
 * Assert a format object's version is supported.
 * Throws UnsupportedFormatVersionError for formats from newer FAM releases.
 */
export function assertFormatSupported(
  obj: Versioned,
  formatName: string,
  maxVersion: string = FAM_VERSION
): void {
  const version = readVersion(obj);
  if (version !== undefined && compareSemver(version, maxVersion) > 0) {
    throw new UnsupportedFormatVersionError(formatName, version, maxVersion);
  }
}
