import { test, expect, describe } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

// ============================================================================
// ⚠️ THE TOOL MUST SAY IT, NOT THE ROADMAP.
//
// Minting a voucher nobody reads breaks nothing — it is inert. The one harm
// available is a BELIEF: someone runs `fam account vouch`, publishes the
// output, and concludes their identity is now verifiable. That is the same
// class as `canReceiveSealed` reading true while nothing sealed.
//
// A PR description cannot correct it, because the belief forms at the moment
// the command succeeds. So the notice lives in the command output — and this
// checks it is actually reached from every path that could produce the belief,
// because the wiring is the part with no test.
// ============================================================================

const SOURCE = readFileSync(join(import.meta.dir, '..', 'commands', 'account.ts'), 'utf8');

/** The file with comments stripped, so prose about the notice cannot satisfy it. */
const code = SOURCE.replace(/\/\*[\s\S]*?\*\//g, '')
  .split('\n')
  .filter((line) => !line.trim().startsWith('//'))
  .join('\n');

describe('the account commands disclose that vouchers are not yet consulted', () => {
  test('the notice exists and says what is not true', () => {
    expect(SOURCE).toMatch(/NOT YET CONSULTED BY ANY CLIENT/);
    // It must name the consequence, not merely flag itself as incomplete.
    expect(SOURCE).toMatch(/does not currently|not yet.*verifiable|still verify/i);
  });

  test('⚠️ BOTH commands reach it — a notice on one path is a notice missed', () => {
    // Comments stripped first: a comment mentioning the function would satisfy
    // a naive count while the call itself was absent.
    const calls = code.match(/printNotYetConsultedNotice\(\)/g) ?? [];

    // One definition site is not a call; the calls are what matter.
    const callSites = calls.length - (code.match(/function printNotYetConsultedNotice/g) ?? []).length;

    expect(callSites).toBeGreaterThanOrEqual(2);
  });

  test('vacuity guard: the source was actually read', () => {
    // Every assertion above passes trivially against an empty string.
    expect(SOURCE.length).toBeGreaterThan(2000);
    expect(code).toContain('runAccountCommand');
  });
});
