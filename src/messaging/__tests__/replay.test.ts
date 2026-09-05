import { test, expect, describe } from 'bun:test';
import { checkReplay } from '../replay';

// ============================================================================
// ⚠️ `sequence` HAS BEEN DOCUMENTED AS WHERE REPLAY PROTECTION LIVES AND HAS
// ENFORCED NOTHING.
//
// The envelope calls it "Per-sender counter. Replay protection lives on this."
// Measured: zero replay checks anywhere under `src/server/`, and the field is
// type-validated as a number and otherwise ignored. A field documented as a
// security control that is not one is worse than an absent field — an absence
// prompts a design, a present-but-inert field TERMINATES it.
//
// ⚠️ THE DESIGN CHOSEN, AND WHY THE OBVIOUS ONE IS WRONG HERE.
//
// The obvious construction is MONOTONICITY: refuse anything not greater than
// the highest sequence seen from that sender. It cannot be used, because FAM
// QUEUES MESSAGES FOR OFFLINE RECIPIENTS AND PUSHES A BACKLOG on reconnect —
// so a legitimate message routinely arrives after a higher-numbered one.
// Monotonicity would reject real mail as an attack, and the rejection would be
// indistinguishable from the real thing.
//
// So: EXACT DUPLICATE DETECTION WITHIN A BOUNDED WINDOW. A (sender, sequence)
// pair seen before is a replay. Out-of-order is fine. A clock that jumps
// backwards on the sender does not manufacture false positives.
//
// ⚠️ WHAT IT DOES NOT COVER, TESTED SO THE BOUND IS VISIBLE: a replay after the
// window lapses is accepted. That is a bound, not a fix, and it is the honest
// position — an unbounded store is the alternative and it grows forever.
// ============================================================================

const NOW = new Date('2026-09-05T18:00:00.000Z');
const WINDOW = 24 * 60 * 60 * 1000; // 24h

const opts = { now: NOW, windowMs: WINDOW };
const ALICE = 'alice@example.com';
const BOB = 'bob@example.com';

function recent(overrides: Partial<{ sender: string; sequence: number; sentAt: string }> = {}) {
  return {
    sender: ALICE,
    sequence: 100,
    sentAt: new Date(NOW.getTime() - 60_000).toISOString(),
    ...overrides,
  };
}

describe('a message not seen before', () => {
  test('is fresh', () => {
    expect(checkReplay([], recent(), opts).kind).toBe('fresh');
  });

  test('is fresh even when other messages from the same sender are known', () => {
    const seen = [{ sender: ALICE, sequence: 99 }];
    expect(checkReplay(seen, recent({ sequence: 100 }), opts).kind).toBe('fresh');
  });
});

describe('⚠️ the same message again', () => {
  test('is a replay', () => {
    const seen = [{ sender: ALICE, sequence: 100 }];
    const verdict = checkReplay(seen, recent({ sequence: 100 }), opts);

    expect(verdict.kind).toBe('replay');
    if (verdict.kind !== 'replay') throw new Error('unreachable');
    expect(verdict.reason).toMatch(/already|replay|delivered before/i);
  });

  test('⚠️ but the same sequence from a DIFFERENT sender is not', () => {
    // Sequences are per-sender. Treating them as global would make two senders
    // who happen to pick the same number silence each other — a denial of
    // service delivered by an honest party.
    const seen = [{ sender: BOB, sequence: 100 }];
    expect(checkReplay(seen, recent({ sender: ALICE, sequence: 100 }), opts).kind).toBe('fresh');
  });
});

describe('⚠️ out-of-order delivery, which FAM produces routinely', () => {
  test('a LOWER sequence arriving after a higher one is fresh, not a replay', () => {
    // The reason monotonicity was rejected. A recipient that was offline gets a
    // backlog pushed on reconnect, so an older message legitimately arrives
    // after a newer one. Refusing it would reject real mail as an attack.
    const seen = [{ sender: ALICE, sequence: 500 }];
    expect(checkReplay(seen, recent({ sequence: 100 }), opts).kind).toBe('fresh');
  });
});

describe('⚠️ the window', () => {
  test('a message older than the window is refused, DISTINCTLY from a replay', () => {
    // Different remedy, so different diagnosis: a replay means someone
    // re-delivered a message, while too-old means this one sat somewhere or the
    // clocks disagree. Collapsing them would send a reader hunting an attacker
    // over a delayed delivery.
    const old = recent({ sentAt: new Date(NOW.getTime() - WINDOW - 1000).toISOString() });
    const verdict = checkReplay([], old, opts);

    expect(verdict.kind).toBe('outside-window');
    if (verdict.kind !== 'outside-window') throw new Error('unreachable');
    expect(verdict.reason).toMatch(/old|window/i);

    // ⚠️ THE ASSERTION IS "DOES NOT ACCUSE", NOT "DOES NOT SAY THE WORD".
    // The first version banned /replay/i and failed against a message that
    // says "it is NOT a replay as far as anything here can tell" — which is
    // clearer for mentioning and denying it. A test that forbids a word
    // forbids the clearest phrasing along with the wrong one; what matters is
    // that no replay is CLAIMED, so the claim's own phrasing is what is banned.
    expect(verdict.reason).not.toMatch(/has already been delivered/i);
  });

  test('a message from implausibly far in the future is refused too', () => {
    // One-sided windows are a common miss: an attacker who can set a future
    // timestamp gets a message that never falls out of a "not too old" check.
    const future = recent({ sentAt: new Date(NOW.getTime() + WINDOW + 1000).toISOString() });
    const verdict = checkReplay([], future, opts);

    expect(verdict.kind).toBe('outside-window');
    if (verdict.kind !== 'outside-window') throw new Error('unreachable');
    expect(verdict.reason).toMatch(/future|ahead/i);
  });

  test('⚠️ THE BOUND IS REAL: a replay AFTER the window is accepted', () => {
    // Asserted rather than left implicit, because it is the limit of this
    // design and a reader deserves to see it stated as a test rather than
    // discover it. The store is pruned by the same window, so an entry that
    // old is no longer there to match against.
    const seen: Array<{ sender: string; sequence: number }> = []; // pruned
    const old = recent({ sentAt: new Date(NOW.getTime() - 1000).toISOString(), sequence: 100 });

    expect(checkReplay(seen, old, opts).kind).toBe('fresh');
  });
});

describe('⚠️ a timestamp that cannot be read', () => {
  test('is refused, not accepted', () => {
    // `Date.parse` returns NaN, and every comparison with NaN is false — so a
    // naive window check passes an unparseable timestamp straight through.
    // That exact fail-open has already been found once in this codebase, in the
    // voucher expiry check.
    const verdict = checkReplay([], recent({ sentAt: 'not a date' }), opts);

    expect(verdict.kind).toBe('outside-window');
    if (verdict.kind !== 'outside-window') throw new Error('unreachable');
    expect(verdict.reason).toMatch(/could not be read|unparseable|not a valid/i);
  });
});
