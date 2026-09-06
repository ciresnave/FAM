import { test, expect, describe, beforeAll, beforeEach } from 'bun:test';
import { mkdtemp, writeFile } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { ChannelPushHandler } from '../channel-push';
import { generateKeyPair, generateEncryptionKeyPair, bufferToBase64 } from '../../../crypto/keys';
import { prepareSealedDirect } from '../../../crypto/outgoing';
import { signVoucher } from '../../../crypto/voucher';
import { containsNowhere } from '../../../testing/allStrings';

// ============================================================================
// ⚠️ WRITTEN AS A SELF-CORRECTION. I CLAIMED THIS PATH WAS COMPLETE AND IT WAS
// ONLY STRUCTURALLY GUARDED.
//
// `readersResolveIdentity.test.ts` checks that the push handler's SOURCE
// mentions `resolveSenderIdentity`. That is a real guard against the call being
// dropped, and it is not evidence that resolution WORKS here — it reads text,
// not behaviour.
//
// ⚠️ AND THE EXISTING PUSH TESTS PASSED BOTH BEFORE AND AFTER RESOLUTION WAS
// WIRED IN, FOR A REASON THAT MATTERS: with no anchor pinned, resolution
// returns `unvouched` and hands back the SERVER's key — byte-identical to the
// old behaviour. So the suite going green after that change proved nothing
// about the change. A test that cannot distinguish the before-state from the
// after-state is not covering the difference.
//
// These exercise the three outcomes that actually differ: vouched, refused on
// disagreement, and unvouched-with-an-anchor-present.
// ============================================================================

const ACCOUNT = 'example.com';
const ALICE = `alice@${ACCOUNT}`;
const BOB = `bob@${ACCOUNT}`;

let aliceIdentity: { publicKey: Uint8Array; privateKey: Uint8Array };
let attackerIdentity: { publicKey: Uint8Array; privateKey: Uint8Array };
let accountKeys: { publicKey: Uint8Array; privateKey: Uint8Array };
let bobEnc: { publicKey: Uint8Array; privateKey: Uint8Array };

let stores: { seenPath: string; anchorsPath: string };

beforeAll(async () => {
  aliceIdentity = await generateKeyPair();
  attackerIdentity = await generateKeyPair();
  accountKeys = await generateKeyPair();
  bobEnc = await generateEncryptionKeyPair();
});

beforeEach(async () => {
  const dir = await mkdtemp(join(tmpdir(), 'fam-pushid-'));
  stores = { seenPath: join(dir, 'seen.json'), anchorsPath: join(dir, 'anchors.json') };
});

/** Pin an account anchor locally, as `fam account trust` would. */
async function pinAnchor(publicKey: string) {
  await writeFile(
    stores.anchorsPath,
    JSON.stringify({
      [ACCOUNT]: {
        publicKey,
        url: 'https://raw.githubusercontent.com/x/x/main/fam/account.pub',
        pinnedAt: new Date().toISOString(),
      },
    })
  );
}

async function voucherBinding(entityPublicKey: string) {
  const now = new Date();
  return signVoucher(bufferToBase64(accountKeys.privateKey), {
    account: ACCOUNT,
    entity: ALICE,
    entityPublicKey,
    issuedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 86_400_000).toISOString(),
    sequence: 1,
  });
}

function fakeMcp() {
  const pushed: Array<{ content: string; meta: any }> = [];
  return {
    pushed,
    server: {
      async notification(n: any) {
        pushed.push({ content: n.params.content, meta: n.params.meta });
      },
    } as any,
  };
}

/**
 * @param servedKey what the RELAY claims Alice's identity key is
 * @param records   what the relay serves as voucher records
 */
function fakeClient(servedKey: string, records: unknown[]) {
  return {
    async listEntities() {
      return [{ id: ALICE, public_key: servedKey }] as any;
    },
    async listVoucherRecords() {
      return records as any;
    },
    async markDelivered() {},
    onMessage() {},
    onUndeliveredMessages() {},
    onInvitation() {},
    offMessage() {},
    offUndeliveredMessages() {},
    offInvitation() {},
  } as any;
}

async function sealedPushFrom(signer: Uint8Array, text: string) {
  const decision = await prepareSealedDirect({
    senderId: ALICE,
    senderIdentityPrivateKey: bufferToBase64(signer),
    recipientId: BOB,
    recipientEncryptionPublicKey: bufferToBase64(bobEnc.publicKey),
    text,
    sequence: Date.now(),
  });
  if (!decision.sealed) throw new Error('fixture should seal');

  return {
    type: 'message' as const,
    from: ALICE,
    channel: null,
    to: BOB,
    text: JSON.stringify(decision.envelope),
    sealed: true,
    timestamp: new Date().toISOString(),
    message_id: 1,
  };
}

function handlerWith(client: any, mcp: any) {
  return new ChannelPushHandler(
    mcp.server,
    client,
    'Bob',
    bufferToBase64(bobEnc.privateKey),
    BOB,
    stores
  );
}

const deliver = (h: ChannelPushHandler, push: unknown): Promise<void> =>
  (h as any).handleMessage(push);

describe('the MCP push path resolves sender identity', () => {
  test('⚠️ a VOUCHED sender opens, and the push says the key was vouched', async () => {
    const alicePublic = bufferToBase64(aliceIdentity.publicKey);
    await pinAnchor(bufferToBase64(accountKeys.publicKey));

    const mcp = fakeMcp();
    const handler = handlerWith(
      fakeClient(alicePublic, [await voucherBinding(alicePublic)]),
      mcp
    );

    await deliver(handler, await sealedPushFrom(aliceIdentity.privateKey, 'vouched body'));

    expect(mcp.pushed[0]!.content).toBe('vouched body');
    expect(mcp.pushed[0]!.meta.sender_vouched).toBe(true);
  });

  test('⚠️ THE ATTACK: the relay serves a DIFFERENT key than the account vouched for', async () => {
    // The relay substitutes its own key for Alice and signs with it. Every
    // signature check passes AGAINST THE SERVED KEY — this is the case the
    // whole voucher tier exists to detect, and the only thing that catches it
    // is the disagreement between what the account vouched for and what the
    // relay served.
    const alicePublic = bufferToBase64(aliceIdentity.publicKey);
    const attackerPublic = bufferToBase64(attackerIdentity.publicKey);
    await pinAnchor(bufferToBase64(accountKeys.publicKey));

    const mcp = fakeMcp();
    const handler = handlerWith(
      // Account vouched for Alice's real key; relay serves the attacker's.
      fakeClient(attackerPublic, [await voucherBinding(alicePublic)]),
      mcp
    );

    await deliver(
      handler,
      await sealedPushFrom(attackerIdentity.privateKey, 'FORGED-BY-RELAY-SENTINEL')
    );

    expect(mcp.pushed[0]!.content).toContain('[not shown]');
    expect(mcp.pushed[0]!.content).toMatch(/differ|disagree|does not match/i);
    // The forged body must not reach the agent by any route.
    expect(containsNowhere(mcp.pushed[0], 'FORGED-BY-RELAY-SENTINEL')).toBe(true);
  });

  test('an anchor with NO records is unvouched — the server key, labelled', async () => {
    // Distinct from the attack: nothing disagrees, there is simply no chain.
    // This is the state every entity is in until someone mints a voucher, and
    // it must still deliver.
    const alicePublic = bufferToBase64(aliceIdentity.publicKey);
    await pinAnchor(bufferToBase64(accountKeys.publicKey));

    const mcp = fakeMcp();
    const handler = handlerWith(fakeClient(alicePublic, []), mcp);

    await deliver(handler, await sealedPushFrom(aliceIdentity.privateKey, 'unvouched body'));

    expect(mcp.pushed[0]!.content).toBe('unvouched body');
    expect(mcp.pushed[0]!.meta.sender_vouched).toBe(false);
  });

  test('control: with NO anchor pinned it still delivers, unvouched', async () => {
    // The pre-existing behaviour, asserted so the tests above are known to
    // differ from it. Without this, all three could be passing for the same
    // reason the OLD suite did.
    const alicePublic = bufferToBase64(aliceIdentity.publicKey);
    // deliberately no pinAnchor()

    const mcp = fakeMcp();
    const handler = handlerWith(fakeClient(alicePublic, []), mcp);

    await deliver(handler, await sealedPushFrom(aliceIdentity.privateKey, 'no anchor body'));

    expect(mcp.pushed[0]!.content).toBe('no anchor body');
    expect(mcp.pushed[0]!.meta.sender_vouched).toBe(false);
  });
});
