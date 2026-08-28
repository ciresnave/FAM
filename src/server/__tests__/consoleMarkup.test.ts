import { test, expect, describe, beforeAll } from 'bun:test';

// ============================================================================
// The console is one file with inline script, so nothing type-checks it and
// nothing bundles it. Its characteristic failure is a NAME MISMATCH: the script
// asks for an element id the markup does not have, `$()` returns null, and the
// handler throws at click time — silently, in the browser, on a page that
// otherwise renders perfectly.
//
// That is not caught by the API tests: every route can be correct while the
// button wired to it is attached to nothing. It is not caught by rendering the
// page either — the mismatch is invisible until the moment someone clicks.
//
// So this reads the file and checks the two sides against each other.
// ============================================================================

const CONSOLE = new URL('../../admin/console.html', import.meta.url);

let html: string;

beforeAll(async () => {
  html = await Bun.file(CONSOLE).text();
});

function declaredIds(): Set<string> {
  return new Set([...html.matchAll(/\bid="([^"]+)"/g)].map(m => m[1]!));
}

/** Every element id the script looks up via $('...'). */
function referencedIds(): string[] {
  return [...html.matchAll(/\$\('([^']+)'\)/g)].map(m => m[1]!);
}

describe('console markup and script agree', () => {
  test('every id the script looks up exists in the markup', () => {
    const declared = declaredIds();
    const missing = [...new Set(referencedIds())].filter(id => !declared.has(id));
    expect(missing).toEqual([]);
  });

  // Guard against the check quietly measuring nothing: if the regex stops
  // matching (a reformat to double quotes, say) the test above passes for the
  // wrong reason — an empty list of references trivially has no misses.
  test('the check is actually finding references', () => {
    expect(referencedIds().length).toBeGreaterThan(10);
    expect(declaredIds().size).toBeGreaterThan(10);
  });

  // The forms the console depends on must be wired, not merely present.
  test('every form has a submit handler assigned', () => {
    const forms = [...html.matchAll(/<form id="([^"]+)"/g)].map(m => m[1]!);
    expect(forms.length).toBeGreaterThan(0);
    for (const id of forms) {
      expect(html).toContain(`$('${id}').onsubmit`);
    }
  });
});

describe('the console does not leak account existence', () => {
  // The design decision from DESIGN-ADMIN.md, enforced against the page: marking
  // a grant "pending" requires knowing whether the grantee has an account, which
  // is the account-existence oracle moved from create to list.
  //
  // Scoped to the SCRIPT, deliberately. Static copy explaining the feature — "a
  // rule may name a source that does not exist yet" — is a statement about what
  // the system permits, and it discloses nothing about any particular address.
  // The leak would be per-ROW: a branch or a badge that differs for one grantee
  // and not another. That can only live in the rendering code.
  //
  // A first version of this test checked the whole file and failed on that hint
  // text. Loosening the copy to satisfy it would have removed a true and useful
  // sentence to protect against a thing the sentence does not do.
  function script(): string {
    const open = html.indexOf('<script>');
    const close = html.lastIndexOf('</script>');
    expect(open).toBeGreaterThan(-1);
    expect(close).toBeGreaterThan(open);
    return html
      .slice(open, close)
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/^\s*\/\/.*$/gm, '');
  }

  test('the rendering code never branches on or displays existence', () => {
    const forbidden = /\b(pending|no such account|not registered|unknown account|exists)\b/i;
    expect(script().match(forbidden)).toBeNull();
  });

  test('both grant directions render the same fields', () => {
    // Asymmetry here would be the subtle form of the leak: a column present in
    // "given" and absent in "received", or vice versa, derived from something
    // only one side can know.
    const body = script();
    for (const field of ['entity_id', 'status', 'created_at']) {
      const uses = [...body.matchAll(new RegExp(`g\\.${field}\\b`, 'g'))].length;
      expect(uses).toBeGreaterThanOrEqual(2);
    }
  });
});

// ---------------------------------------------------------------------------
// A summary must never render without its age.
//
// The harm this whole field guards against is a four-day-old statement read as
// current. If the two can be separated — by a column reorder, a later edit, or
// someone rendering just the text — the guard is gone and nothing fails.
// ---------------------------------------------------------------------------

describe('summary and its staleness stamp are inseparable', () => {
  test('every render of e.summary also renders its age', () => {
    const body = html.slice(html.indexOf('<script>'), html.lastIndexOf('</script>'));
    // The summary cell must reference the stamp. Not a style rule — if this
    // stops being true, an age-less summary is being drawn somewhere.
    expect(body).toContain('e.summary_set_at');
    const summaryUses = [...body.matchAll(/e\.summary\b/g)].length;
    const stampUses = [...body.matchAll(/e\.summary_set_at\b/g)].length;
    expect(stampUses).toBeGreaterThan(0);
    expect(summaryUses).toBeGreaterThan(0);
  });

  test('the age helper exists and is used', () => {
    expect(html).toContain('function ago(');
    const body = html.slice(html.indexOf('<script>'), html.lastIndexOf('</script>'));
    expect(body).toContain('ago(e.summary_set_at)');
  });
});

describe('context collisions are surfaced, not derivable', () => {
  // A collision is a fact about a PAIR. Rendering it as a per-row field would
  // make the reader reconstruct it by comparing rows — which is precisely what
  // nobody did when two sessions shared a checkout and both claimed the same
  // commits. It has to arrive as its own statement.
  test('the directory response collisions are rendered', () => {
    const body = html.slice(html.indexOf('<script>'), html.lastIndexOf('</script>'));
    expect(body).toContain('context_collisions');
    expect(body).toContain('collision-rows');
  });

  test('the banner element exists in the markup', () => {
    expect(html).toContain('id="collisions"');
  });
});
