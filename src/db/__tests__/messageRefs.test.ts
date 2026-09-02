import { test, expect, describe, beforeAll } from 'bun:test';
import { getDatabaseContext } from '../index';
import type { DatabaseContext } from '../transaction';

// ============================================================================
// A typed reference attached to a message.
//
// WHY NOT ATTACHMENTS: not one handoff in the observed portfolio has ever
// needed bytes — documents moved as paths, SHAs, PR numbers and URLs. The
// failure was never transfer. It is that a reference cannot be VERIFIED: "see
// DESIGN.md" does not say which file, at what version, or whether the recipient
// read the thing the sender meant.
//
// THE CORE NEVER INTERPRETS A REFERENCE. It validates STRUCTURE and stores an
// opaque payload. It does not know what `git.ref` means and would accept
// `weird.tenant_slug` on the same terms — the property that keeps FAM a
// federation protocol rather than a git client. Kinds are namespaced for the
// same reason context keys are: a bare `ref` would be FAM claiming a concept.
//
// THE TWO MODES, AND WHY THE RULES ATTACH TO THE MODE RATHER THAN THE KIND:
//
//   verifiable    the recipient RE-FETCHES and compares  -> needs a `digest`
//   reproducible  the recipient can only RE-RUN it       -> needs `construct`,
//                                                           `taken_at`, `taken_as`
//
// Re-running a measurement produces a NEW measurement; it does not confirm the
// old one. A document reference points at something that exists. A measurement
// points at a computation over a state that no longer exists.
//
// `taken_as` IS NOT OPTIONAL, and the case that proves it is three hours old:
// `GET /branches/main/protection` returns 404 "Not Found" to a non-admin and
// 404 "Branch not protected" to an admin. SAME STATUS CODE, OPPOSITE MEANINGS,
// separated only by the body. After any privilege change every absence recorded
// earlier becomes UNVERIFIED — not wrong, unverified — and without the identity
// it was taken as, a stored zero cannot be re-read safely at all.
//
// Requiring these by MODE and not by KIND is what lets the core enforce them
// while staying ignorant: it does not know what a measurement is, only that
// anything claiming to be reproducible must say when, as whom, and over what.
// ============================================================================

const ACCOUNT = 'refs@example.com';
const A = `a@${ACCOUNT}`;
const B = `b@${ACCOUNT}`;

let ctx: DatabaseContext;
let messageId: number;

beforeAll(async () => {
  ctx = getDatabaseContext();
  ctx.db.prepare('INSERT OR IGNORE INTO accounts (id) VALUES (?)').run(ACCOUNT);
  for (const id of [A, B]) {
    ctx.db
      .prepare(
        `INSERT OR IGNORE INTO entities (id, account_id, type, public_key, capabilities)
         VALUES (?, ?, 'agent', 'pk', '{"can_send":true}')`
      )
      .run(id, ACCOUNT);
  }
  const m = await ctx.messages.sendDirectMessage(A, B, 'carrying a reference');
  messageId = m.id;
});

describe('structure is validated; meaning is not', () => {
  test('a verifiable reference round-trips', () => {
    ctx.messageRefs.attach(messageId, {
      kind: 'git.ref',
      mode: 'verifiable',
      payload: { repo: 'ciresnave/FAM', digest: '6f8d67b' },
    });
    const [ref] = ctx.messageRefs.listForMessage(messageId);
    expect(ref!.kind).toBe('git.ref');
    expect(ref!.payload.digest).toBe('6f8d67b');
  });

  // The core would flag, store and return a kind it has never heard of. That is
  // the property keeping repository knowledge out of the protocol.
  test('a kind the core has never heard of is accepted on the same terms', () => {
    expect(() =>
      ctx.messageRefs.attach(messageId, {
        kind: 'weird.tenant_slug',
        mode: 'verifiable',
        payload: { digest: 'acme' },
      })
    ).not.toThrow();
  });

  test('an un-namespaced kind is refused', () => {
    // A bare `ref` would be FAM asserting a concept it does not have.
    expect(() =>
      ctx.messageRefs.attach(messageId, {
        kind: 'ref',
        mode: 'verifiable',
        payload: { digest: 'x' },
      })
    ).toThrow();
  });

  test('a mode outside the two is refused', () => {
    expect(() =>
      ctx.messageRefs.attach(messageId, {
        kind: 'git.ref',
        mode: 'trustworthy' as any,
        payload: { digest: 'x' },
      })
    ).toThrow();
  });

  test('a non-string payload value is refused', () => {
    expect(() =>
      ctx.messageRefs.attach(messageId, {
        kind: 'git.ref',
        mode: 'verifiable',
        payload: { digest: 12345 as any },
      })
    ).toThrow();
  });
});

describe('verifiable references must carry something to compare', () => {
  test('no digest, no reference', () => {
    // Without one the recipient has a name and no way to check they got the
    // thing the sender meant — which is the entire failure this replaces.
    expect(() =>
      ctx.messageRefs.attach(messageId, {
        kind: 'git.ref',
        mode: 'verifiable',
        payload: { repo: 'ciresnave/FAM' },
      })
    ).toThrow(/digest/i);
  });
});

describe('reproducible references must say when, as whom, and over what', () => {
  const complete = {
    construct: 'protected-branch rules on main',
    taken_at: 'origin/main@5ecba5ce',
    taken_as: 'ciresnave-bot',
    value: '0',
  };

  test('a complete one is accepted', () => {
    expect(() =>
      ctx.messageRefs.attach(messageId, {
        kind: 'measurement.count',
        mode: 'reproducible',
        payload: complete,
      })
    ).not.toThrow();
  });

  test('missing CONSTRUCT is refused', () => {
    const { construct, ...rest } = complete;
    expect(() =>
      ctx.messageRefs.attach(messageId, {
        kind: 'measurement.count', mode: 'reproducible', payload: rest,
      })
    ).toThrow(/construct/i);
  });

  test('missing TAKEN_AT is refused', () => {
    const { taken_at, ...rest } = complete;
    expect(() =>
      ctx.messageRefs.attach(messageId, {
        kind: 'measurement.count', mode: 'reproducible', payload: rest,
      })
    ).toThrow(/taken_at/i);
  });

  // The 404 case: same status code, opposite meanings, separated only by the
  // identity that asked. A stored absence without this cannot be re-read after
  // a privilege change.
  test('missing TAKEN_AS is refused', () => {
    const { taken_as, ...rest } = complete;
    expect(() =>
      ctx.messageRefs.attach(messageId, {
        kind: 'measurement.count', mode: 'reproducible', payload: rest,
      })
    ).toThrow(/taken_as/i);
  });

  // The rules attach to the MODE, not the kind — the core does not know what a
  // measurement is, only that a reproducible claim owes these three.
  test('the same requirements bind a kind the core has never seen', () => {
    expect(() =>
      ctx.messageRefs.attach(messageId, {
        kind: 'nonsense.thing', mode: 'reproducible', payload: { value: '1' },
      })
    ).toThrow();
  });
});

describe('references live and die with their message', () => {
  test('deleting the message removes them', async () => {
    const m = await ctx.messages.sendDirectMessage(A, B, 'temporary');
    ctx.messageRefs.attach(m.id, {
      kind: 'git.ref', mode: 'verifiable', payload: { digest: 'abc' },
    });
    expect(ctx.messageRefs.listForMessage(m.id).length).toBe(1);

    ctx.db.prepare('DELETE FROM messages WHERE id = ?').run(m.id);

    expect(ctx.messageRefs.listForMessage(m.id)).toEqual([]);
  });
});
