import { test, expect, describe, beforeAll, afterAll } from 'bun:test';
import { FamClient } from '../client';

// ============================================================================
// ⚠️ WRITTEN AS A SELF-CORRECTION. I CLAIMED "MCP DIRECT MESSAGES TRAVEL
// SEALED" AS COMPLETE AND NOTHING EXERCISED THE MCP SEND PATH AT ALL.
//
// The POLICY is well covered — `sendDirectVia` has unit tests with a fake
// transport, and the CLI's transport is covered end to end against a real
// server. What had no test was the MCP adapter's own transport: whether
// `FamClient` posts a sealed envelope to `/messages/send-sealed` rather than to
// `/messages/send`.
//
// ⚠️ THAT IS EXACTLY THE GAP THAT BIT THIS PROJECT BEFORE. A key-file format
// change was tested on the writer and not on its three readers, and every one
// of them broke: "the format was tested; the readers were not." A shared policy
// with an untested transport is the same shape — the decision is proven and the
// wire is not.
//
// A recording server rather than a mock, because the claim is about which
// ROUTE receives the envelope, and a mock of `request()` would assert my own
// belief about the call rather than the call.
// ============================================================================

const PORT = 17993;
const BASE = `http://127.0.0.1:${PORT}`;

interface Recorded {
  path: string;
  body: any;
}

let recorded: Recorded[] = [];
let server: ReturnType<typeof Bun.serve>;

beforeAll(() => {
  server = Bun.serve({
    port: PORT,
    hostname: '127.0.0.1',
    async fetch(req) {
      const path = new URL(req.url).pathname;
      const body = await req.json().catch(() => null);
      recorded.push({ path, body });
      return Response.json({ message_id: 7, delivery: { outcome: 'pushed' } });
    },
  });
});

afterAll(() => server.stop(true));

function client() {
  recorded = [];
  return new FamClient({ serverUrl: BASE });
}

describe('the MCP client sends a sealed envelope to the sealed route', () => {
  test('⚠️ sendSealedDirectMessage posts to /messages/send-sealed, not /messages/send', async () => {
    // The load-bearing assertion. Posting a sealed envelope to the plaintext
    // route would store the envelope JSON as a message body — it would succeed,
    // and the recipient would receive JSON as though someone had written it.
    const c = client();
    const envelope = { version: 1, sender: 'a@x.com', sealed: { ciphertext: 'zzz' } };

    await c.sendSealedDirectMessage('b@x.com' as any, envelope);

    expect(recorded).toHaveLength(1);
    expect(recorded[0]!.path).toBe('/messages/send-sealed');
    expect(recorded[0]!.path).not.toBe('/messages/send');
  });

  test('the envelope travels under `envelope`, and no `text` field is sent', async () => {
    // `/messages/send-sealed` REFUSES a request carrying both `text` and
    // `envelope` — two fields naming two send paths is an ambiguity the route
    // will not resolve silently. A client that sent both would be rejected, and
    // a client that sent only `text` would have sent plaintext.
    const c = client();
    const envelope = { version: 1, sealed: { ciphertext: 'SENTINEL-CIPHER' } };

    await c.sendSealedDirectMessage('b@x.com' as any, envelope);

    const body = recorded[0]!.body;
    expect(body.envelope).toEqual(envelope);
    expect(body.text).toBeUndefined();
    expect(body.to_entity).toBe('b@x.com');
  });

  test('⚠️ the sealed send carries NO refs field', async () => {
    // `/messages/send-sealed` accepts none: refs live in a server-side table an
    // envelope cannot reach. The adapter refuses the refs-plus-sealing
    // combination upstream rather than dropping them here, so nothing should
    // arrive on this route carrying them.
    const c = client();
    await c.sendSealedDirectMessage('b@x.com' as any, { version: 1 });

    expect(recorded[0]!.body.refs).toBeUndefined();
  });

  test('control: the PLAINTEXT send still goes to /messages/send with text', async () => {
    // Without this, every assertion above could pass against a client that
    // posts everything to the sealed route.
    const c = client();
    await c.sendDirectMessage('b@x.com' as any, 'ordinary text');

    expect(recorded[0]!.path).toBe('/messages/send');
    expect(recorded[0]!.body.text).toBe('ordinary text');
    expect(recorded[0]!.body.envelope).toBeUndefined();
  });

  test('control: a sealed CHANNEL message uses channel_id, not to_entity', async () => {
    const c = client();
    await c.sendSealedChannelMessage('chan-1' as any, { version: 1 });

    expect(recorded[0]!.path).toBe('/messages/send-sealed');
    expect(recorded[0]!.body.channel_id).toBe('chan-1');
    expect(recorded[0]!.body.to_entity).toBeUndefined();
  });
});
