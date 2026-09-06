import { test, expect, describe } from 'bun:test';

// ============================================================================
// Every declared dependency must constrain what it accepts.
//
// THE INCIDENT. `"@types/bun": "latest"` sat in devDependencies. A dist-tag is
// not a range: it accepts whatever the registry points it at, forever, with no
// upper bound of any kind. It is a strictly stronger hijack shape than the
// caret ranges beside it — `^1.81.0` at least refuses a major bump, and
// `latest` refuses nothing.
//
// CI was never the exposure. `.github/workflows/test.yml` runs
// `bun install --frozen-lockfile`, so CI installs whatever `bun.lock` pins
// (1.3.11) regardless of the specifier. The exposure is everyone else:
// `README.md` tells a contributor to run a bare `bun install`, and any
// `bun update` resolves the tag afresh.
//
// ⚠️ WHY THIS IS A TEST AND NOT A NOTE. The problem was already known — it was
// raised in a comment on PR #36 and nowhere else. Measured 2026-09-06 at
// `58ce6196`: the string `types/bun` appears in ZERO markdown or TypeScript
// files in this repository. A finding that lives in a pull-request comment is
// read once, by the people already in that thread, and then it is gone; the
// line it describes stays exactly as it was. Nothing in the tree would ever
// have said so again.
//
// This check is deliberately about SHAPE, not about currency. It does not care
// which version is pinned or whether it is current — only that the specifier
// names a range at all. Upgrading is a decision; accepting anything is not.
// ============================================================================

type Manifest = {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
};

const SECTIONS = [
  'dependencies',
  'devDependencies',
  'peerDependencies',
  'optionalDependencies',
] as const;

async function specifiers(): Promise<Array<{ section: string; name: string; spec: string }>> {
  const manifest = (await Bun.file('package.json').json()) as Manifest;
  const out: Array<{ section: string; name: string; spec: string }> = [];
  for (const section of SECTIONS) {
    for (const [name, spec] of Object.entries(manifest[section] ?? {})) {
      out.push({ section, name, spec });
    }
  }
  return out;
}

/**
 * Does this specifier constrain the versions it will accept?
 *
 * A dist-tag (`latest`, `next`, `beta`) carries no version at all, so it has
 * nothing to constrain. A bare `*` or `x` says so explicitly. And `>=1.2.3`
 * with no upper bound is a range whose ceiling is "every future release",
 * which is the same exposure written differently.
 */
function isBounded(spec: string): boolean {
  const s = spec.trim();
  if (s === '' || s === '*' || s === 'x') return false;
  // A dist-tag has no digits. This also rejects `latest`, `next`, `canary`,
  // and anything else the registry might grow, without a list to keep current.
  if (!/\d/.test(s)) return false;
  // An open upper bound: `>=1.2.3` or `>1.2.3` with nothing capping it.
  if (/^\s*>=?\s*[\d]/.test(s) && !/[<~^]/.test(s)) return false;
  return true;
}

describe('every dependency specifier names a range', () => {
  test('the scan actually finds specifiers', async () => {
    // Without this, an empty manifest read makes the check below pass having
    // examined nothing — the failure shape this repo has spent the most effort
    // on, and the reason `testTimeouts.test.ts` opens the same way.
    const found = await specifiers();
    expect(found.length).toBeGreaterThanOrEqual(4);
    expect(found.some(d => d.section === 'dependencies')).toBe(true);
    expect(found.some(d => d.section === 'devDependencies')).toBe(true);
  });

  test('no dependency accepts an unbounded version', async () => {
    const unbounded = (await specifiers())
      .filter(d => !isBounded(d.spec))
      .map(d => `${d.section}.${d.name} = ${JSON.stringify(d.spec)}`);

    // The message is the finding: a bare `toEqual([])` on a failure prints the
    // offender, which is what a reader needs and all they need.
    expect(unbounded).toEqual([]);
  });

  // The predicate has to be able to say YES and NO, or the check above is a
  // statement about a function that always returns true.
  test('the predicate recognises both answers', () => {
    for (const bounded of ['^1.81.0', '~2.0.0', '1.3.11', '^5', '>=1.2.3 <2', '1.x']) {
      expect(isBounded(bounded)).toBe(true);
    }
    for (const unbounded of ['latest', 'next', 'beta', 'canary', '*', 'x', '', '>=1.2.3', '> 2.0.0']) {
      expect(isBounded(unbounded)).toBe(false);
    }
  });
});
