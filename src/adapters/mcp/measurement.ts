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
// THE FIX IS THAT THERE IS NO PROSE FIELD. `construct` is the COMMAND. A caller
// cannot describe what they counted, because there is nowhere to put a
// description — only the command that produces it. That also makes the
// reference genuinely re-runnable, which is what `reproducible` claimed: a
// recipient cannot re-run prose.
//
// ─────────────────────────────────────────────────────────────────────────────
// THIS ADAPTER DOES NOT RUN THE COMMAND, AND THAT IS A CORRECTION.
//
// The first version had the adapter execute it via `sh -c`, to guarantee the
// value really came from the command. A security review was right to reject it:
// the command arrives as an MCP tool parameter, an agent's context can contain
// untrusted content, and a prompt injection would therefore reach a shell
// THROUGH A MESSAGE-SENDING TOOL. My reasoning had been "the agent can run
// commands anyway" — which is wrong in the way that matters, because when the
// agent runs one it passes through the harness's permission layer and this path
// did not. It turned a messaging tool into a permission-free shell, plus an
// unbounded read and no timeout.
//
// The deeper mistake was building a guarantee the design already provides. A
// `reproducible` reference is verified by the RECIPIENT RE-RUNNING IT — that is
// the definition of the mode. Executing it here bought nothing that re-running
// does not, and paid for it with remote code execution.
//
// So the caller supplies both, and the two protections divide cleanly:
//   paraphrase drift  -> impossible, because there is no prose field
//   a fabricated value -> caught by re-running, which is the mode's contract
// ─────────────────────────────────────────────────────────────────────────────

export interface MeasurementInput {
  /** The command that produces the value. Recorded verbatim as the construct. */
  command: string;
  /** What it produced. An empty string is a real result, not a missing one. */
  value: string;
}

export interface MeasurementRef {
  kind: string;
  mode: 'reproducible';
  payload: Record<string, string>;
}

/**
 * Build a reproducible reference from a command and what it produced.
 *
 * `construct` is the command verbatim. There is no parameter for a caller's own
 * wording of what was counted, which is what makes drift impossible rather than
 * discouraged.
 */
export function buildMeasurementRef(
  input: MeasurementInput,
  context: { takenAt: string; takenAs: string; kind?: string }
): MeasurementRef {
  return {
    kind: context.kind ?? 'measurement.command',
    mode: 'reproducible',
    payload: {
      value: input.value,
      construct: input.command,
      taken_at: context.takenAt,
      taken_as: context.takenAs,
    },
  };
}
