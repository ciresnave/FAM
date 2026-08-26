import { test, expect } from 'bun:test';

// TEMPORARY — deliberately failing.
//
// This exists to prove the CI workflow can go red from the runner. A workflow
// that has never been observed to fail is indistinguishable from one that
// cannot fail: `steps: 0`, a skipped job, a green that reports on nothing.
//
// Removed in the very next commit, after the red run is recorded.
test('CI born-red probe: this assertion is meant to fail', () => {
  expect(1).toBe(2);
});
