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

  const run = line.match(/^\s*run:\s*(.*)$/);
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

console.log(`gates: ${steps.length} step(s) derived from ${WORKFLOW}\n`);

for (const [n, step] of steps.entries()) {
  console.log(`── [${n + 1}/${steps.length}] ${step.name}: ${step.command}`);
  const result = await $`sh -c ${step.command}`.nothrow();
  if (result.exitCode !== 0) {
    console.error(`\ngates: FAILED at "${step.name}" (exit ${result.exitCode}).`);
    process.exit(result.exitCode);
  }
  console.log('');
}

console.log(`gates: all ${steps.length} step(s) passed — this is what CI will run.`);
