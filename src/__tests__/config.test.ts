import { test, expect, describe, afterEach } from 'bun:test';
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

// ============================================================================
// Retention is OFF unless an operator asks for it.
//
// RULED 2026-09-02: no retention. DESIGN.md Open Question 4 closed, open since
// the document was written.
//
// A CHANGE, NOT A CONFIRMATION: the default was 30 days and the sweep ran on a
// timer, so delivered messages had been deleted after a month. Nobody has to
// opt IN to keeping their own data; an operator who wants a lifetime sets one.
// ============================================================================

describe('message retention defaults to keeping everything', () => {
  const original = process.env.FAM_MESSAGE_RETENTION_DAYS;
  afterEach(() => {
    if (original === undefined) delete process.env.FAM_MESSAGE_RETENTION_DAYS;
    else process.env.FAM_MESSAGE_RETENTION_DAYS = original;
  });

  test('unset means no retention', async () => {
    delete process.env.FAM_MESSAGE_RETENTION_DAYS;
    const { messageRetentionDays } = await import('../config');
    expect(messageRetentionDays()).toBe(0);
  });

  test('an operator who sets one gets it', async () => {
    process.env.FAM_MESSAGE_RETENTION_DAYS = '90';
    const { messageRetentionDays } = await import('../config');
    expect(messageRetentionDays()).toBe(90);
  });

  // Deleting on the strength of a typo is the one outcome with no undo.
  test('a malformed value keeps everything rather than guessing', async () => {
    process.env.FAM_MESSAGE_RETENTION_DAYS = 'thirty';
    const { messageRetentionDays } = await import('../config');
    expect(messageRetentionDays()).toBe(0);
  });

  test('a negative value keeps everything too', async () => {
    process.env.FAM_MESSAGE_RETENTION_DAYS = '-5';
    const { messageRetentionDays } = await import('../config');
    expect(messageRetentionDays()).toBe(0);
  });
});
