// What this client has already been delivered.
//
// ⚠️ PRUNED BY THE SAME WINDOW THE CHECK USES, and that coupling is the design
// rather than an optimisation. An unpruned store grows forever; a store pruned
// by a DIFFERENT window than the check would either keep entries the check
// ignores (waste) or drop entries the check still needs (a replay that works).
// One window, read from one place.
//
// Local, like the peer anchors, and for the same reason: what a recipient has
// already seen is the recipient's own knowledge. A relay holding it could
// simply say "no, that is new."

import { homedir } from 'os';
import { join } from 'path';
import { chmod } from 'fs/promises';
import type { SeenMessage } from '../../messaging/replay';

const DEFAULT_PATH = join(homedir(), '.fam', 'seen-messages.json');

interface StoredSighting extends SeenMessage {
  /** When this client saw it. Used for pruning, not for the window check. */
  seenAt: string;
}

async function read(path: string): Promise<StoredSighting[]> {
  const file = Bun.file(path);
  if (!(await file.exists())) return [];
  try {
    const parsed = await file.json();
    return Array.isArray(parsed) ? (parsed as StoredSighting[]) : [];
  } catch {
    // ⚠️ AN UNREADABLE STORE IS AN EMPTY ONE, NOT A CRASH. Failing here would
    // make one corrupt file stop a client reading any mail at all. The cost is
    // named honestly: an empty store accepts everything once, which is the same
    // trust-on-first-use bound a fresh install has.
    return [];
  }
}

/** Sightings still inside the window, oldest first. */
export async function loadSeen(
  now: Date,
  windowMs: number,
  path: string | undefined = DEFAULT_PATH
): Promise<SeenMessage[]> {
  const all = await read(path);
  const cutoff = now.getTime() - windowMs;

  return all
    .filter((s) => {
      const at = Date.parse(s.seenAt);
      // An unparseable sighting is dropped: it cannot be aged, so keeping it
      // forever is the only alternative.
      return Number.isFinite(at) && at >= cutoff;
    })
    .map((s) => ({ sender: s.sender, sequence: s.sequence }));
}

/** Record a sighting, pruning anything that has aged out. */
export async function recordSeen(
  sighting: SeenMessage,
  now: Date,
  windowMs: number,
  path: string | undefined = DEFAULT_PATH
): Promise<void> {
  const all = await read(path);
  const cutoff = now.getTime() - windowMs;

  const kept = all.filter((s) => {
    const at = Date.parse(s.seenAt);
    return Number.isFinite(at) && at >= cutoff;
  });

  kept.push({ ...sighting, seenAt: now.toISOString() });

  await Bun.write(path, JSON.stringify(kept, null, 2));
  try {
    await chmod(path, 0o600);
  } catch {
    // Best effort; meaningless on Windows.
  }
}

/** The window this client checks and prunes by. One value, one place. */
export const REPLAY_WINDOW_MS = 24 * 60 * 60 * 1000;
