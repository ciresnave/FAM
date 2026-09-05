// The recipient's own store of peer account keys.
//
// ─────────────────────────────────────────────────────────────────────────────
// ⚠️ LOCAL, BECAUSE A TRUST DECISION STORED ON THE RELAY IS NOT A TRUST
// DECISION.
//
// DESIGN-FEDERATION: "A recipient verifies a message by checking the entity
// signature, then checking the voucher that binds that entity key to an account
// key IT ALREADY HOLDS. Neither check involves the server that delivered it."
// And: "ACCOUNT KEY — held by the human. Exchanged out-of-band, once, per peer."
//
// `account_key_pins` is a table in the SERVER's database and is deliberately
// left alone here rather than repurposed — it can serve the server's own
// verification, but it cannot serve a recipient's, because the relay is exactly
// the party this tier does not trust.
// ─────────────────────────────────────────────────────────────────────────────
//
// ⚠️ `observePeerAnchor` NEVER UPDATES A PIN, and that rule is the whole point.
// A pin that moved on a new value would detect nothing: an attack and a
// legitimate rotation produce the SAME observation, and the value of pinning is
// that a human is asked which one this is. `changed` is a REPORT, not a state
// transition.
//
// Trust-on-first-use is a real weakness, bounded honestly: the first key is
// taken on faith and every one after it is checked. Strictly better than taking
// every key on faith; strictly worse than an out-of-band fingerprint, which is
// the upgrade path rather than this.

import { homedir } from 'os';
import { join } from 'path';
import { chmod } from 'fs/promises';
import { assertRaw32ByteKey } from '../../types/validation';

const DEFAULT_PATH = join(homedir(), '.fam', 'peer-anchors.json');

interface PeerAnchor {
  publicKey: string;
  url: string;
  pinnedAt: string;
  /** Seen at the anchor but NOT accepted. Never used for verification. */
  pendingPublicKey?: string;
  pendingUrl?: string;
  pendingSeenAt?: string;
}

type AnchorStore = Record<string, PeerAnchor>;

export type PeerAnchorObservation =
  /** First sighting. Taken on faith — the trust-on-first-use step. */
  | { status: 'pinned'; publicKey: string }
  /** Same key as the pin. Nothing to decide. */
  | { status: 'unchanged'; publicKey: string }
  /**
   * A DIFFERENT key at the anchor.
   *
   * ⚠️ A REPORT, NOT A TRANSITION. The pin is untouched and verification keeps
   * using the pinned key until a human accepts the change explicitly.
   */
  | { status: 'changed'; pinned: string; observed: string };

export interface AnchorObservationInput {
  accountId: string;
  publicKey: string;
  /** Where it was seen. Recorded so an accept can be traced to a fetch. */
  url: string;
}

async function readStore(path: string): Promise<AnchorStore> {
  const file = Bun.file(path);
  if (!(await file.exists())) return {};
  try {
    return (await file.json()) as AnchorStore;
  } catch {
    throw new Error(
      `The peer anchor store at ${path} is not readable JSON. Refusing to continue: ` +
        `verification would silently fall back to trusting the server for every peer.`
    );
  }
}

async function writeStore(path: string, store: AnchorStore): Promise<void> {
  await Bun.write(path, JSON.stringify(store, null, 2));
  try {
    await chmod(path, 0o600);
  } catch {
    // Best effort; meaningless on Windows and not worth failing a write over.
  }
}

/**
 * Record what was seen at a peer's anchor, without ever moving an existing pin.
 */
export async function observePeerAnchor(
  input: AnchorObservationInput,
  path: string = DEFAULT_PATH
): Promise<PeerAnchorObservation> {
  assertRaw32ByteKey(input.publicKey, {
    field: `The account key for ${input.accountId}`,
    why: 'An anchor must be a raw 32-byte Ed25519 public key.',
  });

  const store = await readStore(path);
  const existing = store[input.accountId];

  if (!existing) {
    store[input.accountId] = {
      publicKey: input.publicKey,
      url: input.url,
      pinnedAt: new Date().toISOString(),
    };
    await writeStore(path, store);
    return { status: 'pinned', publicKey: input.publicKey };
  }

  if (existing.publicKey === input.publicKey) {
    return { status: 'unchanged', publicKey: existing.publicKey };
  }

  // ⚠️ THE PIN IS NOT TOUCHED. Only the pending observation is recorded, so an
  // accept can later be checked against something actually seen rather than
  // against a value the caller supplied.
  existing.pendingPublicKey = input.publicKey;
  existing.pendingUrl = input.url;
  existing.pendingSeenAt = new Date().toISOString();
  await writeStore(path, store);

  return { status: 'changed', pinned: existing.publicKey, observed: input.publicKey };
}

/** The pinned key for a peer, or null when none is held. */
export async function getPeerAnchorKey(
  accountId: string,
  path: string = DEFAULT_PATH
): Promise<string | null> {
  const store = await readStore(path);
  return store[accountId]?.publicKey ?? null;
}

/**
 * Move a pin to a key that was actually observed at the anchor.
 *
 * ⚠️ REQUIRES THE KEY TO MATCH THE PENDING OBSERVATION. Provenance, not shape.
 * Without it, accepting is setting a pin with extra ceremony, and a caller
 * could pin a key that never came from anywhere — the attack the pin exists to
 * stop, performed through the remedy.
 */
export async function acceptPeerAnchorChange(
  accountId: string,
  publicKey: string,
  path: string = DEFAULT_PATH
): Promise<void> {
  const store = await readStore(path);
  const existing = store[accountId];

  if (!existing) {
    throw new Error(`No anchor is pinned for ${accountId}, so there is no change to accept.`);
  }

  if (!existing.pendingPublicKey) {
    throw new Error(
      `No changed key has been observed for ${accountId}, so there is nothing to accept. ` +
        `Fetch their anchor first — accepting a key that was never seen would make the ` +
        `pin decorative.`
    );
  }

  if (existing.pendingPublicKey !== publicKey) {
    throw new Error(
      `The key offered for ${accountId} is not the one observed at their anchor. ` +
        `Refusing: accepting an unobserved key is the substitution a pin exists to catch.`
    );
  }

  existing.publicKey = existing.pendingPublicKey;
  existing.url = existing.pendingUrl ?? existing.url;
  existing.pinnedAt = new Date().toISOString();
  delete existing.pendingPublicKey;
  delete existing.pendingUrl;
  delete existing.pendingSeenAt;

  await writeStore(path, store);
}
