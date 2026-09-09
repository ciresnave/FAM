import { test, expect, describe } from 'bun:test';

// ============================================================================
// ⚠️ THE RETAINED-BRANCH EXCEPTION, AND THE HALF OF IT THIS REPOSITORY CAN HOLD.
//
// Three branches must never be deleted. `CLAUDE.md` says so in prose, and prose
// is not readable by the thing that would violate it — a sweep that deletes
// "merged branches with no open PR" takes all three, because the CATEGORY they
// fall in and the PROPERTY that matters come apart on exactly these branches.
//
// `.github/retained-branches.json` is the machine-readable half. This file is
// what stops the two halves drifting: a name added or removed on one side and
// not the other reddens here.
//
// ⚠️ WHAT THIS TEST DOES NOT DO, STATED SO NOBODY READS ITS GREEN AS PROTECTION:
// it does not stop a branch being deleted, and it cannot. The sweep that would
// delete one runs in another tool, against the forge, with no knowledge of this
// repository's tests. The protection has two halves and only one is here.
//
// A test that guards the AGREEMENT of a document and a datafile is guarding
// documentation consistency, not branches. Calling it branch protection would
// be the label-with-no-consequence defect this whole exception exists because of.
// ============================================================================

const DATA_PATH = '.github/retained-branches.json';
const DOC_PATH = 'CLAUDE.md';

interface RetainedBranch {
  branch: string;
  reason: string;
  has_other_home: boolean;
}

async function readRetained(): Promise<RetainedBranch[]> {
  const raw = await Bun.file(DATA_PATH).text();
  return (JSON.parse(raw) as { retained: RetainedBranch[] }).retained;
}

describe('⚠️ the retained-branch exception is machine-readable and matches the prose', () => {
  test('the datafile lists branches, and the list is not empty', async () => {
    // A vacuity guard: an empty list would make every assertion below trivially
    // true while protecting nothing, which is exactly the failure mode of a
    // guard nobody forces.
    const retained = await readRetained();
    expect(retained.length).toBeGreaterThan(0);
    for (const r of retained) {
      expect(typeof r.branch).toBe('string');
      expect(r.branch.length).toBeGreaterThan(0);
      expect(typeof r.reason).toBe('string');
      // The property a sweep must check. If this were ever true the branch
      // would not need retaining, and listing it here would be wrong.
      expect(r.has_other_home).toBe(false);
    }
  });

  test('every branch in the datafile is named in CLAUDE.md', async () => {
    // The direction that catches someone adding a branch to the datafile
    // without recording WHY a human should not delete it.
    const doc = await Bun.file(DOC_PATH).text();
    const missing = (await readRetained())
      .map(r => r.branch)
      .filter(b => !doc.includes(b));

    expect(missing).toEqual([]);
  });

  test('⚠️ every branch CLAUDE.md calls retained is in the datafile', async () => {
    // THE DIRECTION THAT MATTERS. A branch documented as retained but absent
    // from the datafile is invisible to any sweep that reads the datafile —
    // which is the whole failure this exception exists to prevent, reproduced
    // by a partial edit.
    //
    // Anchored on the paragraph that names them rather than on the whole file,
    // so an unrelated mention of a branch name elsewhere does not satisfy it.
    const doc = await Bun.file(DOC_PATH).text();
    const marker = 'RETAINED ON PURPOSE';
    expect(doc).toContain(marker); // control: the paragraph still exists

    const paragraph = doc.slice(Math.max(0, doc.indexOf(marker) - 700), doc.indexOf(marker) + 700);
    const named = [...paragraph.matchAll(/`(fix\/[a-z0-9-]+)`/g)].map(m => m[1]!);

    // Control: the extraction found something. A regex that matched nothing
    // would make the comparison below vacuously pass.
    expect(named.length).toBeGreaterThan(0);

    const listed = new Set((await readRetained()).map(r => r.branch));
    const undocumented = [...new Set(named)].filter(b => !listed.has(b));

    expect(undocumented).toEqual([]);
  });
});
