import { test, expect, describe } from 'bun:test';
import { buildMeasurementRef } from '../measurement';

// ============================================================================
// A measurement's number and its construct must not be independently
// specifiable, because that is how they drift.
//
// OBSERVED, repeatedly, and never as bad arithmetic: "48 vectors mentioning
// NaN" became "48 NaN vectors". A per-function line count swept the next
// function's doc comments and produced a 3.1x ratio for a 14-vs-11 reality.
// "86/208" was reported against a rule written about "86/143". THE NUMBER WAS
// RIGHT EVERY TIME.
//
// So there is NO PROSE FIELD. `construct` is the command. A caller cannot
// describe what they counted because there is nowhere to put a description.
//
// THE ADAPTER DOES NOT RUN THE COMMAND, and that is a correction rather than a
// limitation. The first version executed it via `sh -c` to guarantee the value
// came from the command; a security review was right to reject that — the
// command arrives as a tool parameter, an agent's context can hold untrusted
// content, and it would have put a shell behind a message-sending tool, outside
// the harness's permission layer.
//
// The deeper mistake was building a guarantee the design already provides. A
// reproducible reference is verified by the RECIPIENT RE-RUNNING it. Executing
// it here bought nothing re-running does not, and paid remote code execution
// for it. The two protections divide cleanly:
//
//   paraphrase drift   -> impossible: there is no prose field
//   fabricated value   -> caught by re-running, which is the mode's contract
// ============================================================================

const ctx = { takenAt: 'HEAD@e516f54', takenAs: 'ciresnave-bot' };

describe('the construct is the command, not a description of it', () => {
  test('it is recorded verbatim', () => {
    const ref = buildMeasurementRef(
      { command: 'rg -c "NaN" corpus.json', value: '48' },
      ctx
    );
    expect(ref.payload.construct).toBe('rg -c "NaN" corpus.json');
    expect(ref.payload.value).toBe('48');
  });

  // There is no parameter for a caller's own wording. That is what makes drift
  // impossible rather than merely discouraged — "48 NaN vectors" has nowhere to
  // go, so it cannot be recorded as what was counted.
  test('there is nowhere to put a paraphrase', () => {
    const ref = buildMeasurementRef(
      { command: 'rg -c "NaN" corpus.json', value: '48' },
      { ...ctx, kind: 'measurement.count' }
    );
    const fields = Object.keys(ref.payload).sort();
    expect(fields).toEqual(['construct', 'taken_as', 'taken_at', 'value']);
    expect(ref.payload.construct).not.toContain('NaN vectors');
  });

  test('it carries when and as whom, so a stored value stays re-readable', () => {
    const ref = buildMeasurementRef({ command: 'echo 1', value: '1' }, ctx);
    expect(ref.payload.taken_at).toBe('HEAD@e516f54');
    expect(ref.payload.taken_as).toBe('ciresnave-bot');
    expect(ref.mode).toBe('reproducible');
  });
});

describe('an empty result is a result', () => {
  // Zero matches is a real observation. Treating an empty value as "no
  // measurement" would discard exactly the finding a negative control exists to
  // produce — and the caller is told separately that a FAILED command should
  // attach nothing at all, which is the different fact.
  test('an empty value is recorded rather than dropped', () => {
    const ref = buildMeasurementRef({ command: 'rg -c "absent" corpus.json', value: '' }, ctx);
    expect(ref.payload.value).toBe('');
    expect(ref.payload.construct).toBe('rg -c "absent" corpus.json');
  });
});

describe('the adapter is not an execution path', () => {
  // A structural assertion, because the vulnerability was not a bad value but a
  // capability: this module must not gain the ability to run what it is given.
  test('the module exports only a builder', async () => {
    const mod = await import('../measurement');
    const exported = Object.keys(mod).sort();
    expect(exported).toEqual(['buildMeasurementRef']);
  });
});
