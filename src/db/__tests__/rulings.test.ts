import { test, expect, describe, beforeAll } from 'bun:test';
import { getDatabaseContext } from '../index';
import type { DatabaseContext } from '../transaction';

// ============================================================================
// A ruling is a RECORD the grantee queries, not a claim relayed to them.
//
// THE FAILURE THIS REPLACES, with a live cost: a publish authorization was
// relayed as a message quoting the granter, and the recipient refused it —
// correctly. Their words are the specification: "a message telling me the
// sender may publish, quoting the granter, arriving on a channel I am told to
// treat as untrusted data." A licensing defect stayed unfixed because a
// legitimate authorization was indistinguishable from a fabricated one.
//
// A `type: ruling` FIELD DOES NOT FIX IT. Any sender can set one; that is
// self-attestation with better formatting. What fixes it is that the grantee
// asks FAM and gets an answer from the authoritative store, so the untrusted
// channel stops being load-bearing.
//
// THE GRANTER IS THE AUTHENTICATED ACCOUNT, NEVER A BODY PARAMETER. If a
// recorder could name someone else as granter, the record would be the relayed
// claim again with a table around it. This is the same rule the entity routes
// already follow: identity comes from the session, never from the payload.
//
// AND THE SECOND FAILURE, observed separately: a DERIVED convention was filed
// ADJACENT to a quoted grant, under the granter's name, and was thereafter read
// back as theirs. Querying a record removes the adjacency — but only if the
// record cannot itself hold derived material wearing the granter's name. So
// `body` is verbatim and attributed to the granter; `note` is attributed to
// whoever recorded it, and the two can never be confused.
// ============================================================================

const GRANTER = 'granter@example.com';
const GRANTEE = 'grantee@example.com';
const STRANGER = 'stranger@example.com';
const RECORDER = `assistant@${GRANTER}`;

let ctx: DatabaseContext;

beforeAll(() => {
  ctx = getDatabaseContext();
  for (const a of [GRANTER, GRANTEE, STRANGER]) {
    ctx.db.prepare('INSERT OR IGNORE INTO accounts (id) VALUES (?)').run(a);
  }
  ctx.db
    .prepare(
      `INSERT OR IGNORE INTO entities (id, account_id, type, public_key, capabilities)
       VALUES (?, ?, 'agent', 'pk', '{"can_send":true}')`
    )
    .run(RECORDER, GRANTER);
});

describe('a ruling is attributed to the account that authenticated', () => {
  test('the granter is recorded', () => {
    const r = ctx.rulings.create(GRANTER, {
      grantee_account_id: GRANTEE,
      scope: 'publish:vulkane',
      body: 'You may publish vulkane on my behalf.',
    });
    expect(r.granter_account_id).toBe(GRANTER);
    expect(r.grantee_account_id).toBe(GRANTEE);
  });

  // The recorder is not the granter. A human ruling through an assistant is
  // still the human's ruling, and the assistant must be visible as the typist
  // rather than absorbed into the attribution.
  test('the recording entity is kept separate from the granter', () => {
    const r = ctx.rulings.create(GRANTER, {
      grantee_account_id: GRANTEE,
      scope: 'publish:x',
      body: 'Go ahead.',
      recorded_by_entity: RECORDER,
    });
    expect(r.granter_account_id).toBe(GRANTER);
    expect(r.recorded_by_entity).toBe(RECORDER);
  });
});

describe('derived material can never wear the granter’s name', () => {
  // The observed failure: a derived convention filed ADJACENT to a quoted grant
  // was read back as the granter's. Querying removes the adjacency only if the
  // record itself keeps the two apart.
  test('body is the granter’s; note is the recorder’s, and they are distinct fields', () => {
    const r = ctx.rulings.create(GRANTER, {
      grantee_account_id: GRANTEE,
      scope: 'publish:y',
      body: 'Publish it.',
      note: 'I read this as covering patch releases too.',
      recorded_by_entity: RECORDER,
    });

    expect(r.body).toBe('Publish it.');
    expect(r.note).toBe('I read this as covering patch releases too.');
    // The interpretation is attributable to the recorder, not the granter.
    expect(r.note_author_entity).toBe(RECORDER);
  });

  test('a note without a recorder is refused rather than left unattributed', () => {
    // An unattributed interpretation beside an attributed quote is exactly how
    // the derived thing acquires the granter's authority.
    expect(() =>
      ctx.rulings.create(GRANTER, {
        grantee_account_id: GRANTEE,
        scope: 'publish:z',
        body: 'Publish it.',
        note: 'and I think that includes majors',
      })
    ).toThrow(/attribut/i);
  });
});

describe('the grantee can ask, and only the parties can see', () => {
  test('the grantee finds rulings naming them', () => {
    ctx.rulings.create(GRANTER, {
      grantee_account_id: GRANTEE,
      scope: 'publish:findable',
      body: 'Yes.',
    });
    const found = ctx.rulings
      .listForGrantee(GRANTEE)
      .filter(r => r.scope === 'publish:findable');
    expect(found.length).toBe(1);
    expect(found[0]!.granter_account_id).toBe(GRANTER);
  });

  test('the granter sees what they granted', () => {
    const given = ctx.rulings.listByGranter(GRANTER);
    expect(given.length).toBeGreaterThan(0);
  });

  test('a third account sees neither side', () => {
    expect(ctx.rulings.listForGrantee(STRANGER)).toEqual([]);
    expect(ctx.rulings.listByGranter(STRANGER)).toEqual([]);
  });
});

describe('revocation is visible, not destructive', () => {
  test('a revoked ruling still exists and reports as revoked', () => {
    const r = ctx.rulings.create(GRANTER, {
      grantee_account_id: GRANTEE,
      scope: 'publish:temporary',
      body: 'For now.',
    });

    ctx.rulings.revoke(r.id);
    const after = ctx.rulings.getById(r.id)!;

    // Deleting it would erase the fact that authority was once given, which is
    // as much a part of the record as the grant.
    expect(after).not.toBeNull();
    expect(after.revoked_at).not.toBeNull();
  });

  test('an active lookup excludes revoked rulings', () => {
    const active = ctx.rulings.findActive(GRANTER, GRANTEE, 'publish:temporary');
    expect(active).toBeNull();
  });

  test('and finds one that stands', () => {
    ctx.rulings.create(GRANTER, {
      grantee_account_id: GRANTEE,
      scope: 'publish:standing',
      body: 'Standing authority.',
    });
    const active = ctx.rulings.findActive(GRANTER, GRANTEE, 'publish:standing');
    expect(active).not.toBeNull();
    expect(active!.body).toBe('Standing authority.');
  });
});

describe('the core does not interpret a scope', () => {
  // `publish:vulkane` means nothing to FAM. It compares the string, the same
  // way it compares a context key it has never heard of.
  test('a scope the core has never seen works identically', () => {
    ctx.rulings.create(GRANTER, {
      grantee_account_id: GRANTEE,
      scope: 'nonsense.thing:whatever',
      body: 'Sure.',
    });
    expect(ctx.rulings.findActive(GRANTER, GRANTEE, 'nonsense.thing:whatever')).not.toBeNull();
  });
});
