import { test, expect, describe } from 'bun:test';
import { FAM_TOOLS } from '../tools';

// ============================================================================
// ⚠️ A PARAMETER OUTSIDE `properties` IS NOT A PARAMETER, AND NOTHING SAYS SO.
//
// `fam_send_message` carried `measure` and `git_ref` as top-level keys on its
// `inputSchema` instead of inside `properties` — one misplaced brace. Both are
// documented at length, `server.ts` reads both, and neither was ever ADVERTISED
// to a caller: an agent reading the tool definition saw `to_entity`,
// `channel_id`, `text` and nothing else.
//
// Nothing failed. JSON Schema ignores unknown keywords, the MCP SDK passes the
// object through, and the feature simply never appeared. It is the same shape
// as a documented-but-inert `sequence`: the text says the capability is there,
// so no one goes looking for why it is not being used.
//
// This checks the CLASS rather than the two fields, so the next misplaced brace
// fails here instead of shipping silently.
// ============================================================================

/** Keys a tool's inputSchema may legitimately carry at the top level. */
const SCHEMA_KEYWORDS = new Set([
  'type',
  'properties',
  'required',
  'additionalProperties',
  'description',
  '$schema',
]);

describe('every MCP tool declares its parameters where callers can see them', () => {
  test('the tool list is non-empty and every tool has an object schema', () => {
    // Vacuity guard: every assertion below is trivially true of an empty list
    // or of schemas with no `properties` at all.
    expect(FAM_TOOLS.length).toBeGreaterThan(3);
    for (const tool of FAM_TOOLS) {
      expect(tool.inputSchema.type).toBe('object');
      expect(tool.inputSchema.properties).toBeDefined();
    }
  });

  test('⚠️ no tool has a stray key sitting beside `properties`', () => {
    const stray: string[] = [];

    for (const tool of FAM_TOOLS) {
      for (const key of Object.keys(tool.inputSchema)) {
        if (!SCHEMA_KEYWORDS.has(key)) stray.push(`${tool.name}.${key}`);
      }
    }

    // A stray key here is a parameter the tool believes it accepts and no
    // caller can discover.
    expect(stray).toEqual([]);
  });

  test('fam_send_message advertises the parameters its handler reads', () => {
    // The specific regression, kept alongside the general rule: the class check
    // above would pass if someone deleted these fields outright.
    const tool = FAM_TOOLS.find((t) => t.name === 'fam_send_message');
    expect(tool).toBeDefined();

    const declared = Object.keys(tool!.inputSchema.properties);
    for (const name of ['to_entity', 'channel_id', 'text', 'allow_plaintext', 'measure', 'git_ref']) {
      expect(declared).toContain(name);
    }
  });

  test('sealing is documented as the default, and the flag as the exception', () => {
    // The description is what an agent reads to decide whether to pass the
    // flag. If it stopped saying which way the default runs, an agent would
    // have to guess — and the guess that costs is "unsealed unless asked".
    const tool = FAM_TOOLS.find((t) => t.name === 'fam_send_message')!;
    const description = (tool.inputSchema.properties as any).allow_plaintext.description;

    expect(description).toMatch(/sealed by default/i);
    expect(description).toMatch(/refused/i);
  });
});
