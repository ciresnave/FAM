import { test, expect, describe } from 'bun:test';
import { buildRouteMap, type Route } from '../routes';

// ============================================================================
// Route registration must refuse duplicate patterns rather than silently
// dropping one.
//
// The map is keyed by PATTERN alone, so two routes sharing a path meant the
// second overwrote the first with no diagnostic — including across method, so
// a GET and a POST on one path could never coexist and the loser vanished
// quietly. A route that disappears at registration is invisible in exactly the
// way the integration suite's completeness test exists to prevent: that test
// enumerates the routes that REGISTERED, so a route lost here is not merely
// untested, it is unenumerable.
// ============================================================================

const stub = async () => new Response('ok');

describe('buildRouteMap', () => {
  test('registers distinct patterns', () => {
    const routes: Route[] = [
      { method: 'POST', pattern: '/a', handler: stub },
      { method: 'POST', pattern: '/b', handler: stub },
    ];
    expect(buildRouteMap(routes).size).toBe(2);
  });

  test('THROWS on a duplicate pattern rather than dropping one silently', () => {
    const routes: Route[] = [
      { method: 'GET', pattern: '/dup', handler: stub },
      { method: 'POST', pattern: '/dup', handler: stub },
    ];
    expect(() => buildRouteMap(routes)).toThrow(/dup/);
  });

  // The message has to name the pattern, or the failure sends you reading
  // every route group to find which one collided.
  test('the error names the offending pattern', () => {
    const routes: Route[] = [
      { method: 'GET', pattern: '/admin/api/session', handler: stub },
      { method: 'POST', pattern: '/admin/api/session', handler: stub },
    ];
    expect(() => buildRouteMap(routes)).toThrow(/\/admin\/api\/session/);
  });
});
