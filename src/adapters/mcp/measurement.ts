// Building a measurement reference, so the number and what it ranged over
// cannot drift apart.
//
// THE DEFECT THIS EXISTS TO PREVENT, observed repeatedly across the portfolio:
// the arithmetic is correct and the construct it counted was never stated, or
// was stated as a paraphrase that means something else. "48 vectors mentioning
// NaN" became "48 NaN vectors". A per-function line count swept the next
// function's doc comments and produced a 3.1x ratio for a 14-vs-11 reality.
// "86/208" was reported against a rule written about "86/143". THE NUMBER WAS
// RIGHT EVERY TIME.
//
// THE FIX IS STRUCTURAL, and it sharpens what `reproducible` already claimed:
// a reproducible reference whose `construct` is PROSE is not actually
// reproducible, because a recipient cannot re-run a description. If the
// construct is the COMMAND that produced the value, they can — and the two
// cannot drift, because one is derived from the other rather than typed
// alongside it.
//
// Same shape as making the unit a required argument to assertWithinLimit: the
// defect was never a wrong choice, it was that the count and the statement of
// the count were independently specifiable.

/** What a command run produced, whatever its outcome. */
export interface CommandRun {
  command: string;
  stdout: string;
  exitCode: number;
}

export interface MeasurementRef {
  kind: string;
  mode: 'reproducible';
  payload: Record<string, string>;
}

/**
 * Build a reproducible reference from a command that actually ran.
 *
 * `construct` is the command VERBATIM. It is not supplied by the caller and
 * cannot be a paraphrase of it — that is the whole point.
 *
 * Returns null when the command failed. A failed command produced no
 * measurement, and inventing one with an empty value would be a claim about a
 * world nobody observed. The caller reports the failure instead: "could not
 * measure" and "measured zero" are different facts, which is the same
 * distinction the durability check had to learn.
 */
export function buildMeasurementRef(
  run: CommandRun,
  context: { takenAt: string; takenAs: string; kind?: string }
): MeasurementRef | null {
  if (run.exitCode !== 0) return null;

  const value = run.stdout.trim();

  return {
    kind: context.kind ?? 'measurement.command',
    mode: 'reproducible',
    payload: {
      value,
      // Verbatim, and derived from the run rather than described beside it.
      construct: run.command,
      taken_at: context.takenAt,
      taken_as: context.takenAs,
    },
  };
}

/**
 * Why a measurement could not be made, in words the sender will act on.
 *
 * Absence of a claim is honest; absence reported as a zero is not. A caller
 * that cannot tell "the command failed" from "the answer was nothing" will
 * publish the second when the first happened.
 */
export function describeMeasurementFailure(run: CommandRun): string {
  return (
    `measurement NOT attached: \`${run.command}\` exited ${run.exitCode}. ` +
    'No claim was recorded — a failed command produced no measurement, and ' +
    '"could not measure" is not "measured zero".'
  );
}
