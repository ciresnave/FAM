import { test, expect, describe } from 'bun:test';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

// ============================================================================
// ⚠️ THE BRAND IS NOT THE ENFORCEMENT. THIS FILE IS.
//
// A TypeScript brand is advisory: `x as AnchorFetchedKey` compiles, and any
// caller determined to lie can write it. What the brand changes is the DEFAULT
// — passing a fetch result is the natural call, and supplying anything else
// requires an explicit cast.
//
// What makes that a constraint rather than a convention is this test, which
// COUNTS the casts and fails when a second appears. Tonight's most reliable
// finding, across five independent instances, is that a principle held has
// never once been enough and only a step executed has ever worked. So the
// principle "only the anchor fetch may construct this" is written down HERE, as
// something that runs, rather than only in a comment above the type.
//
// ⚠️ AND THE FAILURE THIS PREVENTS IS SPECIFIC. The pin exists so a peer can
// notice its account key changing. If a key from any other source can be
// pinned, the pin records what a caller was TOLD rather than what was SEEN at
// the anchor — and then reports `unchanged` forever, which is worse than no pin
// because it emits confident alerts about a stable world.
// ============================================================================

const SRC = join(import.meta.dir, '..', '..');

/** Every .ts file under src/, excluding tests — which may cast freely. */
function sourceFiles(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      if (entry === '__tests__' || entry === 'node_modules') continue;
      sourceFiles(full, out);
    } else if (entry.endsWith('.ts')) {
      out.push(full);
    }
  }
  return out;
}

describe('only the anchor fetch may construct an AnchorFetchedKey', () => {
  const files = sourceFiles(SRC);

  test('the sweep sees a realistic number of source files', () => {
    // ⚠️ VACUITY GUARD. A file walk that silently returned nothing would make
    // every assertion below pass while checking no code at all — the shape that
    // has bitten this repo before, where a broken query reports a clean result.
    expect(files.length).toBeGreaterThan(30);
  });

  test('exactly ONE construction site exists, and it is the fetch', () => {
    const casts = files
      .map((f) => ({ file: f, hits: countCasts(readFileSync(f, 'utf8')) }))
      .filter((r) => r.hits > 0);

    const total = casts.reduce((n, c) => n + c.hits, 0);
    const where = casts.map((c) => c.file.replace(SRC, 'src').replace(/\\/g, '/'));

    // The message carries the locations, because "expected 1, got 2" without
    // them sends the next person grepping for what this test already knows.
    expect({ total, where }).toEqual({
      total: 1,
      where: ['src/federation/accountKey.ts'],
    });
  });

  test('the guard would notice a second site', () => {
    // ⚠️ A POSITIVE CONTROL FOR THE DETECTOR ITSELF. Without it, a `countCasts`
    // that matched nothing would report "exactly one" as "zero found, and zero
    // is not one" — or worse, a regex that had stopped matching would make the
    // test above pass for a codebase with ten casts in it.
    const sample = `
      const a = something as AnchorFetchedKey;
      const b = other as AnchorFetchedKey;
    `;
    expect(countCasts(sample)).toBe(2);
    expect(countCasts('const c = plain;')).toBe(0);
  });
});

/**
 * Count `as AnchorFetchedKey` casts.
 *
 * Deliberately crude and deliberately NOT sharing an implementation with
 * anything in `src/` — a detector that reused the code it inspects would agree
 * with it by construction.
 */
function countCasts(source: string): number {
  // A negative lookahead rather than a trailing `\b`. ⚠️ Twice today writing
  // that escape through a shell produced a LITERAL BACKSPACE BYTE (0x08),
  // giving a regex that matches nothing — and a detector that matches nothing
  // reports every codebase as clean. The lookahead needs no escape, so it
  // cannot be mangled the same way, and it says the same thing: not part of a
  // longer identifier.
  return (stripComments(source).match(/as\s+AnchorFetchedKey(?![A-Za-z0-9_])/g) ?? []).length;
}

/**
 * Remove line and block comments before counting.
 *
 * ⚠️ ADDED BECAUSE THIS TEST CAUGHT ITSELF. The first version counted raw
 * text, and `provenance.ts` explains the brand by SAYING what a forging cast
 * looks like — so the prose describing the rule registered as a violation of
 * it. Third time today that explanatory text became input to a parser: a bash
 * string terminator, template-literal backticks, and now this.
 *
 * Deliberately crude, and its crudeness is TESTED rather than assumed: it does
 * not understand strings containing comment markers. That limit is acceptable
 * because a cast inside a string literal is not a construction site either.
 */
function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*/g, '');
}
