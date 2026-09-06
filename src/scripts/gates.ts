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

// ⚠️ THE SUITE CAN LOSE A THIRD OF ITSELF AND LOOK LIKE ONE FLAKY TEST.
//
// Measured 2026-09-06: `integration.test.ts` failed to bind its fixed port
// (EADDRINUSE, from client sockets left in TIME_WAIT by the PREVIOUS run), its
// `beforeAll` threw, and all 68 of its tests vanished:
//
//     run 1  Ran 692 tests  1 fail       run 2  Ran 759 tests  0 fail
//     759 - 692 = 67 lost, + 1 reported failed = 68. The arithmetic closes.
//
// The run DID go red, so this is not a silent green. The hazard is subtler, and
// the author of this comment walked into it: a reader sees ONE failure, calls
// it flaky, re-runs, gets green, and never learns that 68 tests did not run.
// A red run does not say HOW MUCH never ran.
//
// TWO CHECKS THAT FAIL ON DIFFERENT THINGS, deliberately. A single count floor
// near today's value reddens on a legitimate deletion, which teaches people to
// raise it — and a guard that fires on correct behaviour gets disarmed.
const RUN_COUNT_FLOOR = 600;

/** `Ran 750 tests across 68 files.` — the runner's own denominator. */
const RAN_LINE = /Ran (\d+) tests across (\d+) files/;

/**
 * A hook that throws reports as a failure with NO TEST NAME and takes the rest
 * of its file with it. Matching that SHAPE rather than one error string means a
 * different cause of the same disappearance still reddens.
 */
const ABORTED_FILE = /\(fail\).*> \(unnamed\)/;

/**
 * ⚠️ A REPO-RELATIVE PATH, BECAUSE TWO PROGRAMS READ IT AND THEY DISAGREE ABOUT
 * EVERYTHING ELSE.
 *
 * The log is WRITTEN by `tee` inside `sh` and READ by `Bun.file`. Two earlier
 * attempts both failed, and the second failed SILENTLY:
 *
 *   1. `process.env.TEMP` — on Windows that is `C:\Users\…`, and the shell ate
 *      the backslashes:
 *          tee: 'C:UsersciresAppDataLocalTemp/…': No such file or directory
 *      Loud, and fixed in minutes.
 *
 *   2. `/tmp` — ⚠️ MSYS `sh` resolves that to the Windows temp directory while
 *      Bun resolves it to `C:\tmp`. `tee` wrote one file, `Bun.file` read a
 *      different, absent one, the `.catch(() => '')` returned empty, and BOTH
 *      DETECTORS BELOW BECAME INERT while gates still reported success.
 *      Found only by forcing the abort case; nothing about the run said so.
 *
 * A relative path is the one form both resolve identically, because both run
 * with the repository root as their working directory.
 */
const logDir = '.gates-logs';
await $`mkdir -p ${logDir}`.nothrow();

for (const [n, step] of steps.entries()) {
  console.log(`── [${n + 1}/${steps.length}] ${step.name}: ${step.command}`);

  // Tee rather than capture: the output still streams live AND all of it is
  // available afterwards. Reading the whole file back is not filtering — a
  // `| tail` here would be, and this script exists because filtered output hid
  // a result once.
  const logPath = `${logDir}/fam-gates-step-${n + 1}.log`;
  const teed = `${step.command} 2>&1 | tee ${logPath}`;
  const result = await $`sh -c ${pipefailPrefix + teed}`.nothrow();

  const output = await Bun.file(logPath).text().catch(() => '');
  const ran = output.match(RAN_LINE);

  // ⚠️ THE DIAGNOSIS IS PRINTED BEFORE THE EXIT, NOT AFTER IT.
  //
  // A first version of this checked `exitCode` first and returned — which meant
  // that when a file DID abort, gates exited on the non-zero code and the
  // explanation never printed. The detector added nothing in precisely the case
  // it exists for, and it would have passed a review because it was never
  // observed in that case.
  //
  // An aborting file always makes the runner exit non-zero, so this is the only
  // ordering in which the message can ever be seen.
  if (ran && ABORTED_FILE.test(output)) {
    console.error(
      `\ngates: ⚠️ A TEST FILE ABORTED at "${step.name}".\n` +
        `  A hook threw, so that file's remaining tests NEVER RAN and are not in\n` +
        `  its count. "${ran[0]}" is a true statement about the tests that were\n` +
        `  ATTEMPTED and says nothing about the ones that were not.\n` +
        `  DO NOT re-run until green — a red that under-reports its own scope is\n` +
        `  a red that gets dismissed. Read ${logPath} whole.`
    );
  }

  if (result.exitCode !== 0) {
    console.error(`\ngates: FAILED at "${step.name}" (exit ${result.exitCode}).`);
    process.exit(result.exitCode);
  }

  // The floor covers the other direction: a run that PASSES while short. It is
  // deliberately far below today's count, because a floor near the current
  // value reddens on a legitimate deletion and teaches people to raise it —
  // and the two checks then fail on different things, which is the point.
  if (ran) {
    const count = Number(ran[1]);
    if (count < RUN_COUNT_FLOOR) {
      console.error(
        `\ngates: FAILED at "${step.name}" — only ${count} tests ran, below the\n` +
          `  floor of ${RUN_COUNT_FLOOR}. The suite PASSING is not the same as the\n` +
          `  suite RUNNING. If this is a deliberate deletion, lower the floor and\n` +
          `  say why; if it is not, something stopped early.`
      );
      process.exit(1);
    }
  }

  console.log('');
}

console.log(`gates: all ${steps.length} step(s) passed — this is what CI will run.`);
