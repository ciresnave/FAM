import { test, expect, describe } from 'bun:test';
import { readdirSync, readFileSync, statSync } from 'fs';
import { join } from 'path';
import {
  DEFAULT_PORT,
  DEFAULT_HOST,
  DEFAULT_SERVER_URL,
  DEFAULT_WS_URL,
  CLAUDE_PEERS_BROKER_PORT,
} from '../config';

// ============================================================================
// Default endpoint configuration
//
// FAM and the claude-peers broker both defaulted to 7899, so they could not run
// side by side. That makes any migration a hard switch with no back-out — a
// single attempt rather than a migration plan.
// ============================================================================

describe('default endpoint configuration', () => {
  test('FAM does not default to the claude-peers broker port', () => {
    expect(DEFAULT_PORT).not.toBe(CLAUDE_PEERS_BROKER_PORT);
  });

  test('derived URLs are built from the default port, not restated', () => {
    expect(DEFAULT_SERVER_URL).toBe(`http://${DEFAULT_HOST}:${DEFAULT_PORT}`);
    expect(DEFAULT_WS_URL).toBe(`ws://${DEFAULT_HOST}:${DEFAULT_PORT}/ws`);
  });

  // The collision existed because the default was written out by hand in 14
  // places. Fixing the number without fixing the duplication just means the
  // next person reintroduces it in one file and nothing notices.
  test('no source file hardcodes the broker port as a FAM default', () => {
    const offenders: string[] = [];

    const walk = (dir: string) => {
      for (const name of readdirSync(dir)) {
        const path = join(dir, name);
        if (statSync(path).isDirectory()) {
          // Tests legitimately mention the broker port (this file names it in a
          // regex). The rule is about production defaults.
          if (name === '__tests__') continue;
          walk(path);
          continue;
        }
        if (!name.endsWith('.ts')) continue;
        // src/config.ts is where the broker port is deliberately named.
        if (path.endsWith(`config.ts`) && dir.endsWith('src')) continue;

        const text = readFileSync(path, 'utf-8');
        text.split('\n').forEach((line, i) => {
          // Standalone 7899 only — test ports like 17899 are not matches.
          if (/(?<![0-9])7899(?![0-9])/.test(line)) {
            offenders.push(`${path}:${i + 1}`);
          }
        });
      }
    };

    walk(join(import.meta.dir, '..'));

    expect(offenders).toEqual([]);
  });
});
