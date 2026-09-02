#!/usr/bin/env bun
// Run locally exactly what CI runs, in CI's order.
//
// WHY THIS EXISTS. Commit d0819a9 was pushed with a green test suite and a
// BROKEN typecheck, and CI caught it in twelve seconds. The suite had been run;
// `tsc` had not. Local verification was a strict SUBSET of the gate, and the
// gap was invisible because everything that was run passed.
//
// That is the second instance of one shape in this repo. The first: `bun test`
// silently ignores bunfig's [test] timeout, so the bare command fails on
// timeouts while the configured one (`bun run test`, --timeout 60000) passes.
// Both times a hand-invoked command answered a NARROWER question than CI's, and
// both times the answer looked like success.
//
// The fix is not "remember to run typecheck". A remembered list drifts from the
// workflow the moment someone adds a step. This script EXTRACTS the commands
// from .github/workflows/test.yml and runs them, so it has no list of its own
// to drift: adding a step to CI adds it here, with no second edit.
//
// It refuses rather than guesses. An unparseable step aborts the run — a local
// gate that silently skips what it cannot read is worse than none, because it
// reports success for work it never examined.

import { $ } from 'bun';

const WORKFLOW = '.github/workflows/test.yml';

const file = Bun.file(WORKFLOW);
if (!(await file.exists())) {
  console.error(`gates: ${WORKFLOW} not found — cannot derive what CI runs.`);
  process.exit(1);
}

const lines = (await file.text()).split(/\r?\n/);

const steps: Array<{ name: string; command: string }> = [];
let pendingName = 'unnamed step';

for (const [i, line] of lines.entries()) {
  const named = line.match(/^\s*-?\s*name:\s*(.+?)\s*$/);
  if (named) {
    pendingName = named[1]!;
    continue;
  }

  // BOTH YAML forms. A step may be written as `run:` under a `- name:`, or
  // inline as `- run:` with no name. This knew only the first, so
  // `- run: bun install --frozen-lockfile` was silently skipped: the script
  // reported "2 steps" against a workflow with three, and said nothing.
  //
  // A gate that omits a line it was meant to protect and still reports success
  // is worse than no gate — and this one's whole premise is that it has no list
  // of its own to drift. It drifted by construction.
  const run = line.match(/^\s*-?\s*run:\s*(.*)$/);
  if (!run) continue;

  const command = run[1]!.trim();

  // A block scalar (`run: |`) spans lines this parser does not read. Refuse
  // loudly: silently skipping it would mean reporting a pass for a step that
  // was never executed, which is the exact failure this script exists to stop.
  if (command === '' || command === '|' || command === '>') {
    console.error(
      `gates: ${WORKFLOW}:${i + 1} uses a multi-line run block, which this ` +
        `script cannot execute faithfully.\n` +
        `       Refusing to continue rather than skipping it silently.\n` +
        `       Either flatten the step to a single command, or teach this ` +
        `script to handle block scalars.`
    );
    process.exit(1);
  }

  // Guard against a loop if someone ever adds this script to the workflow.
  if (/\bgates\b/.test(command)) {
    console.error(`gates: refusing to invoke itself (${WORKFLOW}:${i + 1}).`);
    process.exit(1);
  }

  steps.push({ name: pendingName, command });
  pendingName = 'unnamed step';
}

if (steps.length === 0) {
  console.error(`gates: no run: steps found in ${WORKFLOW}. Refusing to report a pass.`);
  process.exit(1);
}

// VACUITY GUARD ON THE PARSER ITSELF.
//
// Counting the steps we extracted proves nothing about the ones we did not.
// This counts step-looking lines by the crudest possible measure and refuses if
// the real parser found fewer — so the next YAML form nobody anticipated aborts
// the run instead of being quietly dropped, which is exactly what `- run:` did.
//
// Deliberately dumber than the parser and not sharing its regex: a second
// implementation of the same logic would agree with it and prove nothing.
const stepLookingLines = lines.filter(l => l.includes('run:')).length;
if (steps.length < stepLookingLines) {
  console.error(
    `gates: ${WORKFLOW} has ${stepLookingLines} lines containing "run:" but only ` +
      `${steps.length} parsed as steps. Refusing to run a partial gate — one that ` +
      `silently omits a step reports success for work it never examined.\n` +
      `       Teach the parser the missing form rather than relaxing this check.`
  );
  process.exit(1);
}

// PIPEFAIL, so an upstream failure in a pipeline cannot pass as success.
//
// `sh -c 'false | true'` exits 0 — the shell reports only the LAST command, so
// a step like `generate | count` succeeds when the generator failed. No current
// step is a pipeline (measured: three of three), but the instrument was blind
// to the case, and a gate that cannot detect a defect if introduced is not a
// gate against it.
//
// Probed rather than assumed: `set -o pipefail` is not POSIX and a strict `sh`
// rejects it. If it is unavailable we say so loudly instead of running without
// it — a guard that quietly downgrades itself is the shape this exists to stop.
//
// NOTE: GitHub Actions has the same blindness. Its default shell is `bash -e`
// without pipefail, so a pipeline step masks upstream failure in CI too. Fixing
// it here does not fix it there; that needs a `defaults.run.shell` on the
// workflow, and it is recorded rather than assumed done.
const pipefailProbe = await $`sh -c ${'set -o pipefail'}`.nothrow();
const pipefailSupported = pipefailProbe.exitCode === 0;
const pipefailPrefix = pipefailSupported ? 'set -o pipefail; ' : '';

if (!pipefailSupported) {
  console.warn(
    'gates: this shell does not support `set -o pipefail`. A step written as a ' +
      'pipeline will report success even when an upstream command fails. The steps ' +
      'still run; their failure detection is weaker, and you are being told rather ' +
      'than left to assume otherwise.\n'
  );
}

console.log(`gates: ${steps.length} step(s) derived from ${WORKFLOW}\n`);

for (const [n, step] of steps.entries()) {
  console.log(`── [${n + 1}/${steps.length}] ${step.name}: ${step.command}`);
  const result = await $`sh -c ${pipefailPrefix + step.command}`.nothrow();
  if (result.exitCode !== 0) {
    console.error(`\ngates: FAILED at "${step.name}" (exit ${result.exitCode}).`);
    process.exit(result.exitCode);
  }
  console.log('');
}

console.log(`gates: all ${steps.length} step(s) passed — this is what CI will run.`);
