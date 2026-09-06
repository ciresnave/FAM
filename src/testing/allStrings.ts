// Every string reachable inside a value.
//
// ⚠️ EXISTS BECAUSE `JSON.stringify(x).not.toContain(sentinel)` SAYS THE WRONG
// THING. That assertion reads as "serialise this and search the text", when the
// claim is "no string ANYWHERE in this value is, or contains, the forbidden
// body". Key ordering, key names and escaping are all irrelevant to the
// property — and a checker that flags reliance on `JSON.stringify` for stable
// ordering is right that the two are being confused.
//
// Extracted rather than copied: two test files assert this same property about
// forged message bodies, and a second spelling of "did the secret leak" is a
// second answer to a question that must have one.
//
// Lives outside `__tests__` so the runner does not collect it as a suite.

export function allStrings(value: unknown, out: string[] = []): string[] {
  if (typeof value === 'string') out.push(value);
  else if (Array.isArray(value)) for (const v of value) allStrings(v, out);
  else if (value && typeof value === 'object') {
    for (const v of Object.values(value)) allStrings(v, out);
  }
  return out;
}

/** True when no string anywhere in `value` contains `needle`. */
export function containsNowhere(value: unknown, needle: string): boolean {
  return allStrings(value).every((s) => !s.includes(needle));
}
