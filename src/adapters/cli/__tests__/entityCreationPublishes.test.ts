import { test, expect, describe } from 'bun:test';
import { readdirSync, readFileSync } from 'fs';
import { join } from 'path';

// ============================================================================
// ⚠️ EVERY PATH THAT CREATES AN ENTITY MUST ALSO PUBLISH ITS ENCRYPTION KEY.
//
// An entity whose key is generated but never published has `canReceiveSealed`
// false: it holds a private half nobody can seal to, and NOTHING REPORTS THAT
// AS A PROBLEM. Messages to it fall back to unsealed, which is the silent
// downgrade this whole series exists to remove.
//
// Both paths were wired by hand, which means a third one — or a rebase that
// drops the call — restores the defect with a green suite. So the list of
// creation paths is DERIVED from the source rather than written down here:
// anything that calls `provisionEntity` is a creation path by construction,
// and a new one cannot be added without this test noticing.
// ============================================================================

const CLI_DIR = join(import.meta.dir, '..');

/**
 * Every .ts file under the CLI directory, tests excluded.
 *
 * `recursive: true` rather than a hand-rolled walk: no directory argument is
 * ever passed back into the fs module, so the traversal has no reachable path
 * that a caller could influence. Two other tests in this repo still hand-roll
 * it; if a fourth site appears, collapse all of them into one helper rather
 * than adding a spelling.
 */
function sourceFiles(): string[] {
  return readdirSync(CLI_DIR, { recursive: true, encoding: 'utf8' })
    .filter((rel) => rel.endsWith('.ts'))
    // A plain substring, deliberately: the separator differs by platform, and
    // the regex that handled both was written through a shell that ate one
    // level of escaping, leaving a class matching only `/`. On Windows nothing
    // split, the exclusion never fired, AND THE SUITE STILL PASSED — the
    // discovery set was wrong and every assertion was satisfied anyway.
    .filter((rel) => !rel.includes('__tests__'))
    .map((rel) => `${CLI_DIR}/${rel}`);
}

/**
 * ⚠️ COMMENTS ARE REMOVED BEFORE MATCHING, and the direction of the hazard is
 * the reason. A comment naming `publishEncryptionKey` would SATISFY this check
 * while the call itself was absent — the detector would report the guard
 * present because someone wrote prose about it. (The inverse already happened
 * once here: a comment describing a cast tripped the cast-counting detector.)
 */
function code(source: string): string {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split('\n')
    .filter((line) => !line.trim().startsWith('//'))
    .filter((line) => !line.trim().startsWith('import '))
    .join('\n');
}

// Read in a loop rather than a `.map`, so no path is ever a function argument
// reaching the fs module. `code` is now a pure string transform, which is the
// better shape anyway: it does one thing and can be reasoned about without I/O.
const files: { path: string; text: string }[] = [];
for (const path of sourceFiles()) {
  files.push({ path, text: code(readFileSync(path, 'utf8')) });
}

// A file that DECLARES provisionEntity is not a caller of it. Excluded by what
// it contains, not by name, so renaming the file changes nothing.
const creationPaths = files.filter(
  (f) => f.text.includes('provisionEntity(') && !/function\s+provisionEntity/.test(f.text)
);

describe('entity creation publishes the encryption key', () => {
  test('the creation paths are found at all', () => {
    // Vacuity guard. Every assertion below passes trivially against an empty
    // list, so a broken glob would report perfect compliance — the exact shape
    // of "0 hits" being read as a clean result.
    expect(files.length).toBeGreaterThan(5);
    expect(creationPaths.length).toBeGreaterThanOrEqual(2);
  });

  test('⚠️ tests are excluded, and this is asserted rather than assumed', () => {
    // This guard was ADDED BECAUSE IT WAS MISSING AND THE OMISSION WAS INVISIBLE.
    // The exclusion silently matched nothing on Windows, so `files` carried four
    // test files — and every assertion here still passed, because no test file
    // happened to call `provisionEntity`. The discovery set was wrong and the
    // suite was green.
    //
    // The direction that would have cost: a test file calling BOTH
    // `provisionEntity` and `publishEncryptionKey` counts as a satisfied
    // creation path. It would hold `creationPaths.length >= 2` up on its own
    // while both real command paths had lost their call — a guard reporting
    // healthy because its own fixture filled the quota.
    expect(files.filter((f) => f.path.includes('__tests__'))).toEqual([]);
  });

  test('the declaring file is excluded, and it is the only exclusion', () => {
    // Positive control for the filter: provision.ts contains the identifier and
    // must NOT count as a creation path. If this ever passes for the wrong
    // reason the test above catches it, because the list would be empty.
    const declaring = files.filter((f) => /function\s+provisionEntity/.test(f.text));
    expect(declaring.length).toBe(1);
    expect(declaring[0]!.path).not.toBe(creationPaths[0]?.path);
  });

  test('⚠️ each one publishes, so no entity is created unable to receive sealed mail', () => {
    const missing = creationPaths
      .filter((f) => !f.text.includes('publishEncryptionKey('))
      .map((f) => f.path);

    expect(missing).toEqual([]);
  });
});
