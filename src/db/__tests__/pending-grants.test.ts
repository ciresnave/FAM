import { test, expect, describe, beforeAll } from 'bun:test';
import { getDatabaseContext } from '../index';
import type { DatabaseContext } from '../transaction';
import { PermissionChecker } from '../../server/services/permissionChecker';

// ============================================================================
// A grant or rule MAY name a subject that does not exist yet.
//
// Ruled by CireSnave. Two independent reasons, and the second is the one that
// shapes the product:
//
//  1. SECURITY. Creating a grant answered 201 when the grantee account existed
//     and 404 when it did not, so anyone with an account could test any email
//     address and get a definitive answer. That is an account-existence oracle.
//
//  2. WORKFLOW — his reason, and the stronger one: "account A should be able to
//     set up grants and rules for agents that account B hasn't gotten around to
//     creating yet. One shouldn't be forced to wait on the other."
//
// The distinction matters for what gets built. Reason 1 alone produces an
// apologetic "pending" badge; reason 2 makes it an INVITE, which is a feature.
//
// Enforcement was never at the route — it was three foreign keys, so this
// required dropping them (migration 10).
// ============================================================================

const GRANTOR = 'grantor@pending.test';
const NOBODY = 'nobody-has-this-account@pending.test';
const LATER = 'signs-up-later@pending.test';
const EXISTING = 'existing@pending.test';

let ctx: DatabaseContext;
let checker: PermissionChecker;

function account(id: string): void {
  ctx.db.prepare('INSERT OR IGNORE INTO accounts (id) VALUES (?)').run(id);
}

function entity(id: string, accountId: string): void {
  ctx.db
    .prepare(
      `INSERT OR IGNORE INTO entities (id, account_id, type, public_key, capabilities)
       VALUES (?, ?, 'agent', 'pk', '{"can_send":true}')`
    )
    .run(id, accountId);
}

beforeAll(() => {
  ctx = getDatabaseContext();
  checker = new PermissionChecker(ctx);
  account(GRANTOR);
  account(EXISTING);
  entity(`shared@${GRANTOR}`, GRANTOR);
});

describe('grants may name an account that does not exist', () => {
  test('the grant is created rather than refused', () => {
    const grant = ctx.grants.create(GRANTOR, NOBODY, `shared@${GRANTOR}`);
    expect(grant.grantee_account_id).toBe(NOBODY);
  });

  // THE ORACLE CLOSURE. The point is not that both succeed — it is that the
  // caller cannot tell the two apart, which is what makes the email
  // unlearnable. Asserted as a comparison, not as two separate successes.
  test('granting to an unknown email is indistinguishable from a known one', () => {
    const known = ctx.grants.create(GRANTOR, EXISTING, `shared@${GRANTOR}`);
    const unknown = ctx.grants.create(GRANTOR, 'also-nobody@pending.test', `shared@${GRANTOR}`);

    expect(Object.keys(unknown).sort()).toEqual(Object.keys(known).sort());
    expect(unknown.status).toBe(known.status);
  });
});

describe('permission rules may name a source that does not exist', () => {
  test('a rule naming an unknown source ACCOUNT is created', () => {
    const rule = ctx.permissions.create({
      account_id: GRANTOR,
      target_type: 'all',
      source_type: 'account',
      source_account_id: 'blocked-before-they-exist@pending.test',
      action: 'deny',
    });
    expect(rule.source_account_id).toBe('blocked-before-they-exist@pending.test');
  });

  test('a rule naming an unknown source ENTITY is created', () => {
    const rule = ctx.permissions.create({
      account_id: GRANTOR,
      target_type: 'all',
      source_type: 'entity',
      source_entity_id: 'ghost@nowhere.test',
      action: 'deny',
    });
    expect(rule.source_entity_id).toBe('ghost@nowhere.test');
  });
});

// ---------------------------------------------------------------------------
// The workflow this exists for. A pending grant is not a placeholder — it must
// actually confer access the moment the grantee arrives, with no repair step.
// ---------------------------------------------------------------------------

describe('a pending grant is live the moment the grantee appears', () => {
  test('access works after the grantee signs up, with nothing re-run', () => {
    const target = `shared@${GRANTOR}`;
    ctx.grants.create(GRANTOR, LATER, target);

    // ...time passes, and only NOW does that account come into existence.
    account(LATER);
    entity(`agent@${LATER}`, LATER);

    const source = ctx.entities.getById(`agent@${LATER}`)!;
    const granted = ctx.entities.getById(target)!;

    expect(checker.canDirectMessage(source, granted)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// GUARD. Three FKs were dropped, and only three.
//
// This asserts the resulting CONSTRAINT SET, not a behaviour, because the
// obvious behavioural guard is vacuous and I shipped it before checking:
//
//   "deleting the grantor's account still removes their grants"
//
// That passes with the grantor FK REMOVED — verified by mutation, 6/6 still
// green. Deleting an account cascades to its entities, and grants.entity_id ->
// entities removes the grant by a second independent path. The test asserted an
// outcome that TWO constraints can produce, so it could not isolate either, and
// a migration that dropped every foreign key on the table would have passed it.
//
// When a change is defined as "drop exactly these constraints", the check has to
// read the constraints. Anything behavioural is satisfiable by whatever else
// happens to be holding.
// ---------------------------------------------------------------------------

describe('exactly three foreign keys were dropped', () => {
  function fks(table: string): string[] {
    const rows = ctx.db.query(`PRAGMA foreign_key_list(${table})`).all() as {
      table: string;
      from: string;
    }[];
    return rows.map(r => `${r.from} -> ${r.table}`).sort();
  }

  test('grants keeps what the grantor owns and no longer references the grantee', () => {
    expect(fks('grants')).toEqual(['entity_id -> entities', 'grantor_account_id -> accounts']);
  });

  test('permissions keeps the target side and no longer references either source', () => {
    expect(fks('permissions')).toEqual([
      'account_id -> accounts',
      'created_by_entity -> entities',
      'target_entity_id -> entities',
    ]);
  });
});
