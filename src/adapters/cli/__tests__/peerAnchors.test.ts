import { test, expect, describe, beforeEach } from 'bun:test';
import { rm, mkdtemp } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { observePeerAnchor, getPeerAnchorKey, acceptPeerAnchorChange } from '../peerAnchors';
import { generateKeyPair, bufferToBase64 } from '../../../crypto/keys';

// ============================================================================
// ⚠️ THE RECIPIENT'S OWN TRUST STORE, ON THE RECIPIENT'S OWN MACHINE.
//
// DESIGN-FEDERATION is unambiguous: "A recipient verifies a message by checking
// the entity signature, then checking the voucher that binds that entity key to
// an account key IT ALREADY HOLDS. Neither check involves the server that
// delivered it." And: "ACCOUNT KEY — held by the human. Exchanged out-of-band,
// once, per peer."
//
// `account_key_pins` is a table in the SERVER's database. A pin is a trust
// decision, and a trust decision stored on the relay is the shape this whole
// tier exists to avoid. So this is a separate, local store — and the existing
// server-side table is deliberately left alone rather than repurposed.
//
// ⚠️ THE LOAD-BEARING RULE, TAKEN FROM THE SERVER-SIDE PIN BECAUSE IT IS RIGHT:
// `observe` NEVER UPDATES A PIN. A pin that moved on a new value would detect
// nothing — an attack and a legitimate rotation produce the SAME observation,
// and the entire value of pinning is that a human is asked which one this is.
// ============================================================================

let dir: string;
let path: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'fam-anchors-'));
  path = join(dir, 'peer-anchors.json');
  KEY_A = bufferToBase64((await generateKeyPair()).publicKey);
  KEY_B = bufferToBase64((await generateKeyPair()).publicKey);
  KEY_C = bufferToBase64((await generateKeyPair()).publicKey);
});

const ALICE = 'alice@example.com';
const URL_A = 'https://raw.githubusercontent.com/alice/alice/main/fam/account.pub';

// ⚠️ REAL KEYS, NOT HAND-MADE STRINGS. The first version of this file used
// runs of 'A' and 'B' that were the right LENGTH and not valid keys, and
// `assertRaw32ByteKey` rejected all four — correctly. A fixture that only looks
// like the thing under test finds nothing; it also would have hidden the
// validation entirely had the assertion been laxer.
let KEY_A: string;
let KEY_B: string;
let KEY_C: string;

describe('first contact', () => {
  test('is taken on faith, and says so', async () => {
    const observation = await observePeerAnchor(
      { accountId: ALICE, publicKey: KEY_A, url: URL_A },
      path
    );

    expect(observation.status).toBe('pinned');
    expect(await getPeerAnchorKey(ALICE, path)).toBe(KEY_A);
  });

  test('an unknown peer has no key, which is a real answer', async () => {
    // Not an error and not an empty string: "I hold no anchor for this peer"
    // is a fact with a remedy, and an empty key would sail into a verifier and
    // fail as though a message were forged.
    expect(await getPeerAnchorKey('stranger@example.com', path)).toBeNull();
  });
});

describe('⚠️ a key that changes', () => {
  test('does NOT overwrite the pin — it is reported', async () => {
    await observePeerAnchor({ accountId: ALICE, publicKey: KEY_A, url: URL_A }, path);

    const observation = await observePeerAnchor(
      { accountId: ALICE, publicKey: KEY_B, url: URL_A },
      path
    );

    expect(observation.status).toBe('changed');
    // The decisive assertion: the stored key is STILL the original.
    expect(await getPeerAnchorKey(ALICE, path)).toBe(KEY_A);
  });

  test('an unchanged key is reported as unchanged, not as a new pin', async () => {
    await observePeerAnchor({ accountId: ALICE, publicKey: KEY_A, url: URL_A }, path);
    const again = await observePeerAnchor(
      { accountId: ALICE, publicKey: KEY_A, url: URL_A },
      path
    );

    expect(again.status).toBe('unchanged');
  });

  test('⚠️ accepting a change requires the key to MATCH what was observed', async () => {
    // Provenance, not shape. Without this, accepting is setting a pin with
    // extra ceremony — and a caller could pin a key that never came from
    // anywhere, which is the attack the pin exists to stop, performed through
    // the remedy.
    await observePeerAnchor({ accountId: ALICE, publicKey: KEY_A, url: URL_A }, path);
    await observePeerAnchor({ accountId: ALICE, publicKey: KEY_B, url: URL_A }, path);

    // ⚠️ THE MESSAGE IS ASSERTED, NOT JUST THE THROW. A mutant that skipped the
    // "nothing pending" guard still threw — from the provenance check below it,
    // with a DIFFERENT diagnosis — and `rejects.toThrow()` could not tell them
    // apart. Two refusals with opposite explanations reading as one outcome is
    // the same defect as an unknown sender reported as a forgery.
    await expect(acceptPeerAnchorChange(ALICE, KEY_C, path)).rejects.toThrow(
      /not the one observed/i
    );

    // Still the original, because the accept was refused.
    expect(await getPeerAnchorKey(ALICE, path)).toBe(KEY_A);
  });

  test('accepting the observed key does move the pin', async () => {
    await observePeerAnchor({ accountId: ALICE, publicKey: KEY_A, url: URL_A }, path);
    await observePeerAnchor({ accountId: ALICE, publicKey: KEY_B, url: URL_A }, path);

    await acceptPeerAnchorChange(ALICE, KEY_B, path);

    expect(await getPeerAnchorKey(ALICE, path)).toBe(KEY_B);
  });

  test('⚠️ accepting with no pending observation is refused', async () => {
    // Nothing was seen, so there is nothing to accept. Allowing it would let a
    // caller set any key at any time — the pin becomes decoration.
    await observePeerAnchor({ accountId: ALICE, publicKey: KEY_A, url: URL_A }, path);

    await expect(acceptPeerAnchorChange(ALICE, KEY_B, path)).rejects.toThrow(
      /nothing to accept/i
    );
    expect(await getPeerAnchorKey(ALICE, path)).toBe(KEY_A);
  });
});

describe('several peers', () => {
  test('are stored independently', async () => {
    await observePeerAnchor({ accountId: ALICE, publicKey: KEY_A, url: URL_A }, path);
    await observePeerAnchor(
      { accountId: 'bob@example.com', publicKey: KEY_B, url: URL_A },
      path
    );

    expect(await getPeerAnchorKey(ALICE, path)).toBe(KEY_A);
    expect(await getPeerAnchorKey('bob@example.com', path)).toBe(KEY_B);
  });
});
