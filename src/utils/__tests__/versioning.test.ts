import { test, expect, describe } from 'bun:test';
import {
  FAM_VERSION,
  compareSemver,
  stampVersion,
  readVersion,
  isFormatSupported,
  assertFormatSupported,
  type Versioned,
} from '../versioning';
import { UnsupportedFormatVersionError } from '../../types/errors';
import pkg from '../../../package.json';

describe('FAM_VERSION', () => {
  test('matches package.json version', () => {
    expect(FAM_VERSION).toBe(pkg.version);
  });
});

describe('compareSemver', () => {
  test('compares major, minor, patch', () => {
    expect(compareSemver('1.0.0', '1.0.0')).toBe(0);
    expect(compareSemver('1.0.0', '1.0.1')).toBeLessThan(0);
    expect(compareSemver('1.0.1', '1.0.0')).toBeGreaterThan(0);
    expect(compareSemver('1.2.0', '1.10.0')).toBeLessThan(0);
    expect(compareSemver('2.0.0', '1.99.99')).toBeGreaterThan(0);
  });

  test('pre-release sorts before release', () => {
    expect(compareSemver('1.0.0-beta', '1.0.0')).toBeLessThan(0);
    expect(compareSemver('1.0.0', '1.0.0-beta')).toBeGreaterThan(0);
  });

  test('handles missing patch/minor segments as zero', () => {
    expect(compareSemver('1.0', '1.0.0')).toBe(0);
    expect(compareSemver('1', '1.0.0')).toBe(0);
  });
});

describe('stampVersion', () => {
  test('stamps with current FAM version without mutating input', () => {
    const input = { foo: 'bar' };
    const stamped = stampVersion(input);
    expect(stamped.version).toBe(FAM_VERSION);
    expect(input).not.toHaveProperty('version');
    expect(stamped.foo).toBe('bar');
  });
});

describe('isFormatSupported', () => {
  test('accepts legacy formats without a version', () => {
    expect(isFormatSupported({ data: 1 } as unknown as Record<string, unknown> & Versioned)).toBe(true);
  });

  test('accepts current and older versions', () => {
    expect(isFormatSupported({ version: FAM_VERSION })).toBe(true);
    expect(isFormatSupported({ version: '0.0.1' })).toBe(true);
  });

  test('rejects newer versions', () => {
    const newer = '999.0.0';
    expect(isFormatSupported({ version: newer })).toBe(false);
  });
});

describe('assertFormatSupported', () => {
  test('passes for legacy and compatible versions', () => {
    expect(() => assertFormatSupported({}, 'TestFormat')).not.toThrow();
    expect(() => assertFormatSupported({ version: FAM_VERSION }, 'TestFormat')).not.toThrow();
  });

  test('throws UnsupportedFormatVersionError for newer formats', () => {
    expect(() => assertFormatSupported({ version: '999.0.0' }, 'TestFormat')).toThrow(
      UnsupportedFormatVersionError
    );
  });

  test('error message names the format and versions', () => {
    try {
      assertFormatSupported({ version: '999.0.0' }, 'EncryptedKeyFile');
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(UnsupportedFormatVersionError);
      const err = e as UnsupportedFormatVersionError;
      expect(err.message).toContain('EncryptedKeyFile');
      expect(err.message).toContain('999.0.0');
      expect(err.statusCode).toBe(500);
    }
  });
});

describe('readVersion', () => {
  test('reads string version', () => {
    expect(readVersion({ version: '1.2.3' })).toBe('1.2.3');
  });

  test('returns undefined for legacy formats', () => {
    expect(readVersion({})).toBeUndefined();
    expect(readVersion({ version: 42 } as unknown as Versioned)).toBeUndefined(); // non-string ignored
  });
});
