import { test, expect, describe, beforeAll } from 'bun:test';
import { getDatabaseContext } from '../../../db';
import { MessageSendService } from '../messageSend';
import { PermissionChecker } from '../permissionChecker';
import type { DatabaseContext } from '../../../db/transaction';

// ============================================================================
// Grant revocation racing a DM send.
//
// sendDirectMessage checks the permission synchronously and then AWAITS the
// persist. Anything that runs in that await window sees a decision that has
// already been made against state that may since have changed.
//
// READ THE LABELS. Each test below is marked DEMONSTRATION or EVIDENCE:
//
//   DEMONSTRATION — the interleaving is forced, so the test proves the window
//                   EXISTS and what happens when something lands in it. It says
//                   nothing about how often that occurs in production.
//   EVIDENCE      — the interleaving is not forced. Passing means the invariant
//                   held across the orderings that actually occurred, which is
//                   weaker than proving it holds across all of them.
//
// Where an ordering is forced, it is forced AT THE ASSERTION and said so there.
// A concurrency test that passes because the timing happened to work is the
// same defect as any other test that cannot fail for the reason it claims.
// ============================================================================

const GRANTOR = 'grantor@revrace.test';
const GRANTEE = 'grantee@revrace.test';
const SENDER = `s@${GRANTEE}`;
const TARGET = `t@${GRANTOR}`;

let ctx: DatabaseContext;
let service: MessageSendService;

function countMessages(): number {
  return (ctx.db.prepare('SELECT COUNT(*) c FROM messages').get() as { c: number }).c;
}

function freshGrant(): void {
  ctx.db.prepare('DELETE FROM grants').run();
  ctx.grants.create(GRANTOR, GRANTEE, TARGET);
}

function revokeNow(): void {
  ctx.db.prepare("UPDATE grants SET status = 'revoked' WHERE entity_id = ?").run(TARGET);
}

beforeAll(() => {
  ctx = getDatabaseContext();
  for (const acct of [GRANTOR, GRANTEE]) {
    ctx.db.prepare('INSERT OR IGNORE INTO accounts (id) VALUES (?)').run(acct);
  }
  ctx.db
    .prepare(
      `INSERT OR IGNORE INTO entities (id, account_id, type, public_key, capabilities)
       VALUES (?, ?, 'agent', 'pk', '{"can_send":true}')`
    )
    .run(SENDER, GRANTEE);
  ctx.db
    .prepare(
      `INSERT OR IGNORE INTO entities (id, account_id, type, public_key, capabilities)
       VALUES (?, ?, 'agent', 'pk', '{"can_send":true}')`
    )
    .run(TARGET, GRANTOR);

  const wsStub = { pushToEntity() {} } as any;
  service = new MessageSendService(ctx, wsStub, new PermissionChecker(ctx));
});

describe('baseline — no race involved', () => {
  test('a live grant permits the DM', async () => {
    freshGrant();
    const before = countMessages();
    await service.sendDirectMessage(SENDER, TARGET, 'permitted');
    expect(countMessages()).toBe(before + 1);
  });

  test('a revoked grant refuses the DM', async () => {
    freshGrant();
    revokeNow();
    const before = countMessages();
    expect(service.sendDirectMessage(SENDER, TARGET, 'refused')).rejects.toThrow();
    await Bun.sleep(10);
    expect(countMessages()).toBe(before);
  });
});

describe('revocation landing inside the check-to-persist window', () => {
  // DEMONSTRATION. The ordering is FORCED: revokeNow() runs in the same
  // synchronous block immediately after sendDirectMessage() returns its
  // promise, so it is guaranteed to execute before the awaited persist
  // resumes. That proves the window exists and is wide enough to matter.
  //
  // It does NOT show how often this ordering occurs in production, where the
  // revocation is a separate HTTP request and must win a real event-loop race.
  test('DEMONSTRATION: a message must not be persisted under a grant revoked before the write', async () => {
    freshGrant();
    const before = countMessages();

    // --- forced ordering starts here ---
    const sending = service.sendDirectMessage(SENDER, TARGET, 'raced').catch(() => null);
    revokeNow(); // runs before the awaited persist resumes, by construction
    await sending;
    // --- forced ordering ends here ---

    // The invariant, not the sequence: whatever the interleaving, no message
    // exists that only a revoked grant would have permitted.
    expect(countMessages()).toBe(before);
  });

  // EVIDENCE. Not forced — the revocation is scheduled as a separate task and
  // has to win the race on its own. Passing means the invariant held for the
  // orderings that actually happened on this machine, this run. It is not a
  // proof that it holds for every ordering.
  test('EVIDENCE: the invariant holds across unforced interleavings', async () => {
    let violations = 0;

    for (let i = 0; i < 25; i++) {
      freshGrant();
      const before = countMessages();

      const sending = service.sendDirectMessage(SENDER, TARGET, `unforced-${i}`).catch(() => null);
      // Scheduled rather than inline: this may land before or after the persist.
      setTimeout(revokeNow, 0);
      await sending;

      const persisted = countMessages() > before;
      const grantLive =
        ctx.grants.findActive(GRANTOR, GRANTEE, TARGET) !== null &&
        ctx.grants.findActive(GRANTOR, GRANTEE, TARGET) !== undefined;

      // A message may legitimately exist if the revocation lost the race. The
      // violation is a message that exists while the grant is already gone.
      if (persisted && !grantLive) violations++;
    }

    expect(violations).toBe(0);
  });
});
