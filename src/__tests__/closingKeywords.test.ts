import { test, expect, describe, beforeAll } from 'bun:test';
import { Glob } from 'bun';

// ============================================================================
// A CLOSING KEYWORD HAS NO TENSE.
//
// On 2026-09-09 issue 54 — the flap-protection deferral — closed itself as
// COMPLETED with nothing implemented. The cause was a sentence in a comment
// warning that a future fix would close it, phrased with the keyword directly
// before the number. A development commit message repeated that phrasing, the
// squash commit aggregated it, and GitHub acted on the warning as if it were a
// declaration.
//
// ⚠️ THE SURFACE WAS NOT THE ONE ANYONE CHECKS. The pull request body never
// mentioned the issue; its declared closures were correct. A squash commit
// message carries EVERY commit message from the branch, so a line written in a
// development commit — never reviewed as a closing declaration — closed an
// issue at merge time.
//
// So "will close", "would close" and "must not close" are all read the same
// way. The convention is to name an issue without a verb adjacent to it, and
// this is the guard rather than a note asking people to remember.
//
// ⚠️ IT IS A GUARD BECAUSE A NOTE ALREADY FAILED. The first draft of the fix
// for this defect quoted the offending wording inside its own explanation,
// putting a live instance of the hazard into the fix for the hazard. A sweep
// caught it; re-reading the paragraph did not. A fourth instance, which nobody
// had written that day, had been sitting in a design document since it merged.
// ============================================================================

/**
 * GitHub's closing keywords, immediately followed by an issue reference.
 *
 * A LITERAL, not a constructed `RegExp`. Assembling it from a keyword array
 * read better and bought nothing: the list is fixed by GitHub, not by us.
 *
 * ⚠️ Note what the literal does NOT contain — a keyword next to an actual
 * NUMBER. `#\d+` is a pattern, so this file does not match itself and needs no
 * exclusion. An exclusion would be a hole in the check shaped exactly like the
 * thing being checked, in the one file guaranteed to discuss the pattern.
 */
const ADJACENT = /\b(close[sd]?|fix(e[sd])?|resolve[sd]?)\b\s*:?\s*#\d+/i;

/**
 * The surface a commit message might quote: our own source and our own prose.
 *
 * Globs rather than a hand-rolled directory walk, matching testTimeouts.test.ts.
 * The patterns are explicit so a reader can see the population without running
 * it, and so nothing wanders into node_modules.
 */
const PATTERNS = ['src/**/*.ts', 'shared/**/*.ts', '*.ts', '*.md'];

const scanned: string[] = [];
const offenders: string[] = [];

beforeAll(async () => {
  for (const pattern of PATTERNS) {
    for await (const rel of new Glob(pattern).scan('.')) {
      scanned.push(rel);
      const text = await Bun.file(rel).text();
      text.split('\n').forEach((line, i) => {
        if (ADJACENT.test(line)) offenders.push(`${rel}:${i + 1}`);
      });
    }
  }
});

describe('no closing keyword sits next to an issue number', () => {
  // ⚠️ VACUITY GUARD, separate on purpose. `expect(offenders).toEqual([])` is
  // exactly as green against a sweep that examined nothing, and "the sweep is
  // broken" and "a file reintroduced the phrasing" call for opposite responses.
  test('the sweep actually examines files', () => {
    expect(scanned.length).toBeGreaterThan(30);
    // Prose is the half that gets quoted into commit messages, and globbing it
    // is the half most likely to break silently.
    expect(scanned.filter((p) => p.endsWith('.md')).length).toBeGreaterThan(3);
  });

  // Without this, a regex that stopped matching would report perfect
  // compliance. Synthetic, so it cannot go stale with the tree. The forbidden
  // strings are ASSEMBLED, so building the control does not commit the offence.
  test('the matcher recognises the phrasing it looks for', () => {
    const bad = (verb: string, n: number) => `the change that lands ${verb}` + ' #' + n;
    expect(ADJACENT.test(bad('will close', 54))).toBe(true);
    expect(ADJACENT.test(bad('Fixes', 12))).toBe(true);
    expect(ADJACENT.test(bad('resolved:', 7))).toBe(true);

    // And does not fire on the safe forms the convention asks for.
    expect(ADJACENT.test('tracked in #54, and repeated here')).toBe(false);
    expect(ADJACENT.test('issue 54 went with it')).toBe(false);
    expect(ADJACENT.test('the closing behaviour is described in #54')).toBe(false);
  });

  test('no tracked file puts a closing keyword before an issue number', () => {
    expect(offenders).toEqual([]);
  });
});
