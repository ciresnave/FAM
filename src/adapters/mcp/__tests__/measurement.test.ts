import { test, expect, describe } from 'bun:test';
import { buildMeasurementRef, describeMeasurementFailure } from '../measurement';

// ============================================================================
// A measurement's number and its construct must not be independently
// specifiable, because that is how they drift.
//
// OBSERVED, repeatedly, across the portfolio: the arithmetic correct and the
// construct never stated, or stated as a paraphrase meaning something else.
// "48 vectors mentioning NaN" became "48 NaN vectors". A per-function line
// count swept the next function's doc comments and produced a 3.1x ratio for a
// 14-vs-11 reality. "86/208" was reported against a rule written about
// "86/143". THE NUMBER WAS RIGHT EVERY TIME.
//
// So `construct` is the COMMAND, derived from the run, never a caller-supplied
// description of it. This also makes `reproducible` mean what it claimed: a
// recipient cannot re-run prose, but they can re-run a command.
//
// Same fix as making the unit a required argument to assertWithinLimit — the
// defect was never a wrong choice, it was that the count and the statement of
// the count could be written separately.
// ============================================================================

const ctx = { takenAt: 'origin/main@e516f54', takenAs: 'ciresnave-bot' };

describe('the construct is the command, not a description of it', () => {
  test('it is copied verbatim from the run', () => {
    const ref = buildMeasurementRef(
      { command: 'rg -c "NaN" corpus.json', stdout: '48\n', exitCode: 0 },
      ctx
    )!;
    expect(ref.payload.construct).toBe('rg -c "NaN" corpus.json');
    expect(ref.payload.value).toBe('48');
  });

  // The caller cannot supply a construct at all. There is no parameter for it,
  // which is what makes drift impossible rather than discouraged.
  test('a caller cannot substitute their own wording', () => {
    const ref = buildMeasurementRef(
      { command: 'rg -c "NaN" corpus.json', stdout: '48\n', exitCode: 0 },
      { ...ctx, kind: 'measurement.count' }
    )!;
    // "48 NaN vectors" is the paraphrase that caused the incident. The only
    // thing recordable here is what actually ran.
    expect(ref.payload.construct).not.toContain('NaN vectors');
    expect(ref.payload.construct).toBe('rg -c "NaN" corpus.json');
  });

  test('it carries when and as whom, so a stored value stays re-readable', () => {
    const ref = buildMeasurementRef({ command: 'echo 1', stdout: '1', exitCode: 0 }, ctx)!;
    expect(ref.payload.taken_at).toBe('origin/main@e516f54');
    expect(ref.payload.taken_as).toBe('ciresnave-bot');
    expect(ref.mode).toBe('reproducible');
  });
});

describe('a failed command produces no measurement', () => {
  // "Could not measure" and "measured zero" are different facts. Recording an
  // empty value would be a claim about a world nobody observed — the same
  // distinction the durability check had to learn.
  test('null rather than a zero', () => {
    expect(
      buildMeasurementRef({ command: 'rg -c "NaN" missing.json', stdout: '', exitCode: 2 }, ctx)
    ).toBeNull();
  });

  test('an empty stdout from a SUCCEEDING command is still a measurement', () => {
    // Zero matches with exit 0 is a real observation and must not be discarded
    // alongside the failures — that would erase exactly the finding a negative
    // control exists to produce.
    const ref = buildMeasurementRef(
      { command: 'rg -c "absent" corpus.json', stdout: '', exitCode: 0 },
      ctx
    );
    expect(ref).not.toBeNull();
    expect(ref!.payload.value).toBe('');
  });

  test('the failure is described for the sender rather than swallowed', () => {
    const msg = describeMeasurementFailure({ command: 'false', stdout: '', exitCode: 1 });
    expect(msg).toMatch(/NOT attached/i);
    expect(msg).toContain('false');
    expect(msg).toMatch(/measured zero/i);
  });
});
