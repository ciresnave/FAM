import { test, expect, describe } from 'bun:test';
import { readdirSync, readFileSync } from 'fs';
import { join } from 'path';

// ============================================================================
// ⚠️ EVERY READER MUST RESOLVE THE SENDER, NOT TRUST THE DIRECTORY.
//
// `entities.public_key` is a column in the SERVER's own database, served over
// `/entities/list`. A malicious home server needs nobody's private key — it
// publishes its own key for an entity and forges freely. An INVALID key would
// fail verification and be noticed; a VALID substituted one is undetectable.
// That asymmetry is the whole reason the voucher tier exists.
//
// So a reader that passes a directory key straight into `readIncoming` has
// terminated its signature check at a value the relay controls. Both readers
// were wired by hand, which means a third one — or a rebase that drops the
// call — restores the defect with a green suite.
//
// The list of readers is DERIVED: anything calling `readIncoming` is a reader
// by construction, and one cannot be added without this noticing.
//
// This replaces a test that guarded the temporary "vouchers are not consulted
// yet" notice. That notice became FALSE when these readers were wired, so it
// was removed — and the guard was replaced rather than deleted, because the
// invariant it protects outlived the notice.
// ============================================================================

const SRC = join(import.meta.dir, '..', '..');

function sourceFiles(): string[] {
  return readdirSync(SRC, { recursive: true, encoding: 'utf8' })
    .filter((rel) => rel.endsWith('.ts'))
    .filter((rel) => !rel.includes('__tests__'))
    .map((rel) => `${SRC}/${rel}`);
}

/** Comments stripped, so prose about resolution cannot satisfy the check. */
function code(source: string): string {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split('\n')
    .filter((line) => !line.trim().startsWith('//'))
    .filter((line) => !line.trim().startsWith('import '))
    .join('\n');
}

const files = sourceFiles().map((path) => ({ path, text: code(readFileSync(path, 'utf8')) }));

// A file that DEFINES readIncoming is not a reader of it.
const readers = files.filter(
  (f) => f.text.includes('readIncoming(') && !/function readIncoming/.test(f.text)
);

describe('every reader resolves the sender identity', () => {
  test('the readers are found at all', () => {
    // Vacuity guard: every assertion below passes against an empty list.
    expect(files.length).toBeGreaterThan(10);
    expect(readers.length).toBeGreaterThanOrEqual(2);
  });

  test('tests are excluded from the discovery', () => {
    expect(files.filter((f) => f.path.includes('__tests__'))).toEqual([]);
  });

  test('⚠️ none of them verifies against a key the relay supplied alone', () => {
    const trusting = readers
      .filter((f) => !f.text.includes('resolveSenderIdentity'))
      .map((f) => f.path);

    expect(trusting).toEqual([]);
  });
});
