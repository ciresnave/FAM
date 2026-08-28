import { test, expect, describe, beforeAll } from 'bun:test';
import { Glob } from 'bun';

// ============================================================================
// No test may quietly give itself LESS time than the project allows.
//
// THE INCIDENT. Three crypto tests carried `}, 15000)` — the only per-test
// timeout overrides in the codebase — sitting on the three slowest tests in the
// suite (Argon2id at 64MB/t=3/p=4, twice each). A per-test timeout OVERRIDES
// the CLI flag, so the tests the project deliberately gave 60 seconds were
// running on 15, and under concurrent load they intermittently blew it.
//
// The failure that produced was worse than a slow test. "fails decryption with
// wrong passkey" going red READS as a negative control passing — as decryption
// succeeding with the wrong key — when it actually meant the test was killed
// before its assertion ran. A timeout on a security test is indistinguishable
// at a glance from that test discovering something terrible, and it cost two
// people an evening of suspicion.
//
// A larger override is fine: a genuinely slow test asking for MORE room is a
// deliberate act. The defect is asking for less than the project already
// decided, which is almost always accidental — a number copied from somewhere
// it made sense.
// ============================================================================

/** The project-wide budget, read from the script CI actually runs. */
async function projectTimeout(): Promise<number> {
  const pkg = (await Bun.file('package.json').json()) as { scripts: Record<string, string> };
  const match = pkg.scripts.test?.match(/--timeout\s+(\d+)/);
  expect(match).not.toBeNull();
  return Number(match![1]);
}

/** Per-test timeout arguments: the `}, 15000);` that closes a test call. */
function overridesIn(source: string): number[] {
  return [...source.matchAll(/^\s*\}(?:\s*,\s*)(\d+)\s*\)\s*;?\s*$/gm)].map(m => Number(m[1]));
}

let files: string[] = [];
let budget = 0;

beforeAll(async () => {
  budget = await projectTimeout();
  const glob = new Glob('src/**/*.test.ts');
  for await (const f of glob.scan('.')) files.push(f);
});

describe('per-test timeouts never undercut the project budget', () => {
  test('the scan actually finds test files', () => {
    // Without this, an empty file list makes the check below pass vacuously —
    // which is the shape of failure this repo has spent the most effort on.
    expect(files.length).toBeGreaterThan(10);
    expect(budget).toBeGreaterThan(0);
  });

  test('no test gives itself less time than the suite allows', async () => {
    const offenders: Array<{ file: string; timeout: number }> = [];

    for (const file of files) {
      const source = await Bun.file(file).text();
      for (const value of overridesIn(source)) {
        if (value < budget) offenders.push({ file, timeout: value });
      }
    }

    expect(offenders).toEqual([]);
  });

  // The parser has to be able to see an override, or the check above is a
  // statement about a regex that matches nothing.
  test('the override parser recognises the form it is looking for', () => {
    const sample = [
      "test('slow thing', async () => {",
      '  await work();',
      '}, 15000);',
    ].join('\n');
    expect(overridesIn(sample)).toEqual([15000]);

    // And does not fire on an ordinary test close.
    expect(overridesIn("test('x', () => {\n  ok();\n});")).toEqual([]);
  });
});
