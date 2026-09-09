import { test, expect, describe } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

// ============================================================================
// ⚠️ DEFERRAL DETECTORS — THE CATEGORY THIS PROJECT HAD NEVER BUILT.
//
// Measured by an external audit: ZERO deferral-marker constructs in this tree,
// under six spellings, against 1373 `expect(` calls in test files. Every guard
// here is about behaviour that EXISTS. Nothing marked behaviour that does not.
// That was a choice nobody had made deliberately.
//
// ⚠️ THESE ARE TRIPWIRES, NOT ASSERTIONS ABOUT CORRECTNESS. Each one is GREEN
// while its deferral is outstanding and goes RED when the work is DONE — and
// its failure message names its own deletion and the document to update. The
// point is that finishing the work forces the paperwork, rather than leaving a
// stale "not built yet" behind, which this project has already been bitten by
// three times.
//
// ⚠️ AND EACH IS FORCED IN BOTH DIRECTIONS BEFORE BEING TRUSTED. A deferral
// detector spends its ENTIRE LIFE in the state where it has nothing to say, so
// its green-and-retire branch has never executed even once — which is exactly
// the condition under which an unreachable print goes unnoticed for months.
// That defect shipped in this repo's own gate script and was caught only by
// forcing it: the abort check sat after an early exit and could never fire in
// the case it existed for.
//
// A tripwire that fires on the CORRECT final state is deliberate. It should be
// deleted by the person who reaches that state, and the message tells them so.
// ============================================================================

const ROOT = join(import.meta.dir, '..', '..');

// ⚠️ EACH TRIPWIRE READS ITS DOCUMENT BY NAME, rather than through a
// `read(rel)` helper. Two reasons, and the second is the one that matters:
// a helper taking a path parameter is indistinguishable from one forwarding a
// caller-supplied path, which a scanner is right to flag — and inlining makes
// the subject of each tripwire visible at the assertion instead of one
// indirection away. A tripwire whose document you cannot see is one nobody can
// check the deletion instruction against.

describe('deferral: account_key_pins should be renamed', () => {
  // OWNER: FAM lane.
  // WHY DEFERRED: renaming a table is a migration; the disclaimer is the
  // honest interim. Recorded at src/db/schema.ts, at the table definition.
  test('⚠️ TRIPWIRE — delete this when the table is renamed', () => {
    const schema = readFileSync(join(ROOT, 'src', 'db', 'schema.ts'), 'utf8');

    const stillNamedPins = schema.includes('CREATE TABLE IF NOT EXISTS account_key_pins');
    const disclaimerPresent = schema.includes('NOT** A RECIPIENT');

    if (!stillNamedPins) {
      throw new Error(
        'account_key_pins appears to have been RENAMED. That is the deferred work, and ' +
          'this tripwire has done its job.\n' +
          '  DELETE: this test.\n' +
          '  ALSO DELETE: the "NOT a recipient trust anchor" disclaimer at the table ' +
          'definition in src/db/schema.ts — it exists only because the name was misleading, ' +
          'and a disclaimer outliving its reason is the stale-note defect it was written for.'
      );
    }

    // While the rename is outstanding, the disclaimer must be there. It is the
    // only thing standing between the name and a contributor wiring
    // verification to a table that lives in the RELAY's database.
    expect(disclaimerPresent).toBe(true);
  });
});

describe('deferral: replay protection is bounded by a window', () => {
  // OWNER: FAM lane.
  // WHY DEFERRED: the upgrade is a durable per-sender counter agreed by both
  // sides, which removes the window rather than widening it. Recorded in
  // src/messaging/replay.ts.
  test('⚠️ TRIPWIRE — delete this when a persisted counter replaces the window', () => {
    const replay = readFileSync(join(ROOT, 'src', 'messaging', 'replay.ts'), 'utf8');

    // The bound is stated in the module. If the counter is built, the module
    // stops being window-based and this text goes with it.
    const windowStillTheMechanism = replay.includes('windowMs');
    const boundStillDocumented = replay.includes('A replay AFTER the window lapses is accepted');

    if (!windowStillTheMechanism) {
      throw new Error(
        'replay.ts no longer works by a time window, which suggests the durable per-sender ' +
          'counter was built. That is the deferred work.\n' +
          '  DELETE: this test.\n' +
          '  UPDATE: the "WHAT THIS DOES NOT COVER" block in src/messaging/replay.ts — its ' +
          'four bounds describe the window, and three of them stop being true.\n' +
          '  UPDATE: the sequence note in src/messaging/directSend.ts and ' +
          'src/messaging/channelSend.ts, which both say the value is NOT a security control.'
      );
    }

    expect(boundStillDocumented).toBe(true);
  });
});

describe('deferral: Phase 7.5 is parked behind Phase 5', () => {
  // OWNER: FAM lane.
  // WHY DEFERRED: 7.2's server attestation stops being sufficient once a ruling
  // crosses to a server the recipient does not control, so 7.5 cannot be
  // scheduled ahead of federation. Recorded in ROADMAP.md.
  test('⚠️ TRIPWIRE — delete this when federation lands', () => {
    const roadmap = readFileSync(join(ROOT, 'ROADMAP.md'), 'utf8');

    const stillUnscheduled = roadmap.includes('7.5 unscheduled');
    const dependencyStillRecorded = roadmap.includes('BLOCKING DEPENDENCY ON PHASE 5');

    if (!stillUnscheduled) {
      throw new Error(
        'ROADMAP no longer marks 7.5 unscheduled. If federation landed, the parking reason ' +
          'is discharged.\n' +
          '  DELETE: this test.\n' +
          '  CHECK: the "BLOCKING DEPENDENCY ON PHASE 5" note in ROADMAP.md still describes ' +
          'a real constraint — it says entity-signed rulings need a verifiable ' +
          'account→entity chain, and that chain now exists.'
      );
    }

    expect(dependencyStillRecorded).toBe(true);
  });
});

describe('⚠️ deferral: whoami reaches lanes only as they restart — DETECTOR: NONE', () => {
  // OWNER: FAM lane.
  // ⚠️ NO DETECTOR IS POSSIBLE FROM THIS REPOSITORY, and that is recorded here
  // rather than papered over with a weak one.
  //
  // The completion condition is "every peer has restarted at least once", and
  // its subject is OTHER AGENTS' PROCESSES. Nothing in this tree can observe
  // them. An unscheduled event can be given a detector by scheduling it; a
  // subject the tree cannot see cannot.
  //
  // ⚠️ A WEAK DETECTOR HERE WOULD BE WORSE THAN NONE: it would convert "nobody
  // is watching this" into "something is watching this", and only the first is
  // true. The two available real moves are to make the subject observable (a
  // process reports in, and the ABSENCE of a report is the red) or to convert
  // the deferral into one about something the tree CAN see (the code path that
  // consumes whoami refuses until it has one). Neither is built.
  test('the admission is recorded in ROADMAP, where readers look', () => {
    // ⚠️ THIS ASSERTION FIRST READ THIS FILE AND CHECKED IT CONTAINED
    // "DETECTOR: NONE" — WHICH IS WRITTEN IN THE ASSERTION ITSELF. It was
    // true by construction and could not fail: forcing it edited the subject
    // and the check together, and 4 tests still passed. A self-referential
    // guard is the purest form of the vacuity this file exists to prevent,
    // and it was in this file.
    //
    // The subject is now a DIFFERENT document, so the check can fail — and the
    // admission sits where someone looking for project status will find it,
    // rather than only in a test nobody opens.
    const roadmap = readFileSync(join(ROOT, 'ROADMAP.md'), 'utf8');

    expect(roadmap).toContain('Deferrals with NO DETECTOR');
    expect(roadmap).toContain('DETECTOR: NONE');
    // Named, so deleting the entry while keeping the heading still reddens.
    expect(roadmap).toContain('whoami` reaches a lane only when that lane restarts');
  });
});

describe('deferral: the server send path does not verify a voucher', () => {
  // OWNER: FAM lane.
  // WHY DEFERRED: the chain is wired into the CLI and the MCP adapter through
  // `resolveSenderIdentity`, but `src/server/services/messageSend.ts` still
  // consults it zero times, so anything routed through the server rests on the
  // relay's word for entity identity. Recorded in DESIGN-FEDERATION.md.
  //
  // ⚠️ THIS TRIPWIRE EXISTS BECAUSE THE CLAIM IT GUARDS ALREADY WENT STALE ONCE,
  // SILENTLY. DESIGN-FEDERATION.md asserted "NOTHING CALLS ANY OF IT" of five
  // symbols; by 2026-09-09 three of them had real call sites and a fourth
  // (`resolveVoucherChain`) had never existed under that name. Nothing pinned
  // the paragraph — only ROADMAP.md and CLAUDE.md are read by tests — so the
  // document aged while the code moved underneath it.
  //
  // ⚠️ The subject is a SOURCE FILE, not this test and not the document making
  // the claim. A guard that reads the file its own assertion is written in is
  // true by construction, which this file has already been bitten by once.
  test('⚠️ TRIPWIRE — delete this when the server send path verifies vouchers', () => {
    const sendPath = readFileSync(
      join(ROOT, 'src', 'server', 'services', 'messageSend.ts'),
      'utf8'
    );

    // Non-vacuity: if the file stops looking like the send service, this test is
    // measuring nothing and should say so rather than pass.
    expect(
      sendPath.length,
      'messageSend.ts is unexpectedly small — repoint this tripwire rather than trusting it'
    ).toBeGreaterThan(200);

    const consultsChain =
      sendPath.includes('resolveEntityKey') ||
      sendPath.includes('resolveSenderIdentity') ||
      sendPath.includes('voucher') ||
      sendPath.includes('Voucher');

    if (consultsChain) {
      throw new Error(
        'The SERVER send path now references the voucher chain. That is the deferred work, ' +
          'and this tripwire has done its job.\n' +
          '  DELETE: this test.\n' +
          '  ALSO UPDATE: DESIGN-FEDERATION.md — the "entity identity still rests on the ' +
          'relay\'s word" conclusion, and the 2026-09-09 correction above it, both describe ' +
          'a server that does not verify. If it now does, that whole section is the stale ' +
          'one, and a stale "not built" is the direction this project has already been ' +
          'bitten by three times.'
      );
    }

    expect(consultsChain).toBe(false);
  });
});
