import { test, expect, describe, beforeAll } from 'bun:test';
import { getDatabaseContext } from '../index';
import type { DatabaseContext } from '../transaction';

// ============================================================================
// An adapter-populated context bag, and collision detection over it.
//
// THE MEASURED HARM: two sessions sharing one checkout, mutually invisible,
// both claiming authorship of the same three commits. The network held both
// `cwd` values the entire time and had no way to say so. 9 of 18 sessions were
// sharing a checkout with at least one sibling.
//
// FAM CORRECTLY HAS NO cwd OR REPO CONCEPT — those do not belong in a
// federation protocol, and the fix must not smuggle them in. So the core stores
// an OPAQUE map of namespaced keys to strings and compares them for equality.
// It never parses a path, never knows which key means "working directory", and
// would detect a collision on any key an adapter chose to publish. The MCP
// adapter is the only thing here that knows what `mcp.cwd` is.
//
// Keys must be namespaced precisely so the core stays ignorant: `mcp.cwd`
// belongs to the MCP adapter, and a bare `cwd` would be a claim about a concept
// FAM does not have.
//
// SCOPE: context is exposed for an account's OWN entities only. A collision
// between two of your sessions is operationally useful; publishing your
// filesystem paths to every account you have been granted to is a disclosure
// nobody asked for, and the harm being fixed was always same-operator.
// ============================================================================

const ACCOUNT = 'ctx@example.com';
const OTHER = 'ctx-other@example.com';
const A = `a@${ACCOUNT}`;
const B = `b@${ACCOUNT}`;
const C = `c@${ACCOUNT}`;
const FOREIGN = `f@${OTHER}`;

let ctx: DatabaseContext;

beforeAll(() => {
  ctx = getDatabaseContext();
  for (const acct of [ACCOUNT, OTHER]) {
    ctx.db.prepare('INSERT OR IGNORE INTO accounts (id) VALUES (?)').run(acct);
  }
  for (const [id, acct] of [[A, ACCOUNT], [B, ACCOUNT], [C, ACCOUNT], [FOREIGN, OTHER]] as const) {
    ctx.db
      .prepare(
        `INSERT OR IGNORE INTO entities (id, account_id, type, public_key, capabilities)
         VALUES (?, ?, 'agent', 'pk', '{"can_send":true}')`
      )
      .run(id, acct);
  }
});

describe('the context bag is opaque and namespaced', () => {
  test('an entity starts with no context', () => {
    expect(ctx.entities.getById(C)!.context).toBeNull();
  });

  test('a namespaced map round-trips unchanged', () => {
    ctx.entities.updateContext(A, { 'mcp.cwd': 'C:/Projects/fam', 'mcp.git_root': 'C:/Projects/fam' });
    expect(ctx.entities.getById(A)!.context).toEqual({
      'mcp.cwd': 'C:/Projects/fam',
      'mcp.git_root': 'C:/Projects/fam',
    });
  });

  test('null clears it', () => {
    ctx.entities.updateContext(C, { 'mcp.cwd': '/tmp' });
    ctx.entities.updateContext(C, null);
    expect(ctx.entities.getById(C)!.context).toBeNull();
  });

  // The namespace is what keeps the core ignorant. A bare `cwd` would be FAM
  // asserting it has a concept of a working directory, which it must not.
  test('an un-namespaced key is refused', () => {
    expect(() => ctx.entities.updateContext(A, { cwd: '/somewhere' })).toThrow();
  });

  test('a non-string value is refused', () => {
    expect(() => ctx.entities.updateContext(A, { 'mcp.pid': 1234 as any })).toThrow();
  });

  test('an oversized bag is refused rather than truncated', () => {
    const big: Record<string, string> = {};
    for (let i = 0; i < 200; i++) big[`mcp.k${i}`] = 'x'.repeat(100);
    expect(() => ctx.entities.updateContext(A, big)).toThrow();
  });
});

describe('collisions are detected by equality, not by understanding', () => {
  test('two entities sharing a value collide on that key', () => {
    ctx.entities.updateContext(A, { 'mcp.cwd': 'C:/Projects/shared' });
    ctx.entities.updateContext(B, { 'mcp.cwd': 'C:/Projects/shared' });

    const collisions = ctx.entities.findContextCollisions(ACCOUNT);
    const cwd = collisions.find(c => c.key === 'mcp.cwd' && c.value === 'C:/Projects/shared');

    expect(cwd).toBeDefined();
    expect(cwd!.entity_ids.sort()).toEqual([A, B].sort());
  });

  test('differing values do not collide', () => {
    ctx.entities.updateContext(A, { 'mcp.cwd': 'C:/Projects/one' });
    ctx.entities.updateContext(B, { 'mcp.cwd': 'C:/Projects/two' });
    expect(ctx.entities.findContextCollisions(ACCOUNT)).toEqual([]);
  });

  test('an entity alone on a value is not a collision', () => {
    ctx.entities.updateContext(A, { 'mcp.cwd': 'C:/Projects/solo' });
    ctx.entities.updateContext(B, null);
    expect(ctx.entities.findContextCollisions(ACCOUNT)).toEqual([]);
  });

  // The core compares strings. It would flag a collision on any key at all,
  // which is the property that keeps filesystem knowledge out of it.
  test('it collides on a key FAM has never heard of', () => {
    ctx.entities.updateContext(A, { 'weird.tenant_slug': 'acme' });
    ctx.entities.updateContext(B, { 'weird.tenant_slug': 'acme' });

    const found = ctx.entities.findContextCollisions(ACCOUNT);
    expect(found.some(c => c.key === 'weird.tenant_slug')).toBe(true);
  });
});

describe('context does not cross an account boundary', () => {
  test('a foreign entity sharing a value is NOT reported', () => {
    ctx.entities.updateContext(A, { 'mcp.cwd': 'C:/Projects/crossing' });
    ctx.entities.updateContext(B, null);
    ctx.entities.updateContext(FOREIGN, { 'mcp.cwd': 'C:/Projects/crossing' });

    // Detecting this would mean telling one account holder that a stranger's
    // session runs from the same path — a disclosure nobody asked for, and the
    // harm being fixed was always same-operator.
    const collisions = ctx.entities.findContextCollisions(ACCOUNT);
    expect(collisions).toEqual([]);
  });

  test('the other account sees nothing either', () => {
    expect(ctx.entities.findContextCollisions(OTHER)).toEqual([]);
  });
});

describe('the context bound is measured in the unit it reports', () => {
  // Found by following a complexity finding on an unrelated method. The bound
  // counted JavaScript CHARACTERS and reported BYTES — the identical defect
  // caught in message references during review, fixed there and left standing
  // here, which is what having two copies of one rule means.
  //
  // A non-ASCII path is not exotic: C:\Проекты\... is an ordinary cwd.
  test('a multibyte bag within the character count but over the byte limit is refused', () => {
    const wide = '中'.repeat(1500); // 1500 characters, 4500 bytes
    expect(() => ctx.entities.updateContext(A, { 'mcp.cwd': wide })).toThrow(/bytes/i);
  });

  test('an ASCII bag of the same character count is still accepted', () => {
    const narrow = 'a'.repeat(1500); // 1500 characters, 1500 bytes
    expect(() => ctx.entities.updateContext(A, { 'mcp.cwd': narrow })).not.toThrow();
  });
});
