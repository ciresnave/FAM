import { test, expect, describe } from 'bun:test';
import { readdirSync, readFileSync, statSync } from 'fs';
import { join } from 'path';

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
// So "will close", "would close", "must not close" and "closed" are all read as
// "close". The convention is to name an issue without a verb adjacent to it,
// and this is the guard rather than a note asking people to remember.
//
// ⚠️ IT IS A GUARD BECAUSE A NOTE ALREADY FAILED. The first draft of the fix
// for this defect quoted the offending wording inside its own explanation,
// putting a live instance of the hazard into the fix for the hazard. A sweep
// caught it; re-reading the paragraph did not.
// ============================================================================

/** GitHub's closing keywords, immediately followed by an issue reference. */
const KEYWORDS = ['close', 'closes', 'closed', 'fix', 'fixes', 'fixed', 'resolve', 'resolves', 'resolved'];
const ADJACENT = new RegExp(`\\b(${KEYWORDS.join('|')})\\b\\s*:?\\s*#\\d+`, 'i');

/**
 * Control strings are ASSEMBLED rather than written out, so that this file's
 * own source never contains the phrasing it forbids.
 *
 * ⚠️ The alternative — write the literal and exclude this file from the sweep —
 * puts a hole in the check shaped exactly like the thing being checked, and the
 * hole is in the one file guaranteed to talk about the pattern.
 */
const bad = (verb: string, n: number) => `the change that lands ${verb}` + ' #' + n;

const ROOT = join(import.meta.dir, '..', '..');

/** Source and prose that a commit message might quote. */
function scanTargets(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name === '.git' || name === '.claude') continue;
    const path = join(dir, name);
    if (statSync(path).isDirectory()) {
      scanTargets(path, out);
      continue;
    }
    if (name.endsWith('.ts') || name.endsWith('.md')) out.push(path);
  }
  return out;
}

const scanned = scanTargets(ROOT);
const offenders = scanned.flatMap((path) => {
  const lines = readFileSync(path, 'utf-8').split('\n');
  return lines
    .map((line, i) => ({ line, i }))
    .filter(({ line }) => ADJACENT.test(line))
    .map(({ i }) => `${path.replace(ROOT, '.')}:${i + 1}`);
});

describe('no closing keyword sits next to an issue number', () => {
  // ⚠️ VACUITY GUARD, separate on purpose. `expect(offenders).toEqual([])` is
  // exactly as green against a walk that examined nothing, and "the sweep is
  // broken" and "a file reintroduced the phrasing" call for opposite responses.
  test('the sweep actually examines files', () => {
    expect(scanned.length).toBeGreaterThan(30);
  });

  // Without this, a regex that stopped matching would report perfect
  // compliance. Synthetic, so it cannot go stale with the tree.
  test('the matcher recognises the phrasing it looks for', () => {
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
