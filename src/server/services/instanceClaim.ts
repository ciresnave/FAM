// Which running process holds an identity.
//
// ─────────────────────────────────────────────────────────────────────────────
// ⚠️ THE QUESTION NO KEY CAN ANSWER. See `DESIGN-INSTANCE-IDENTITY.md`.
//
// A duplicated agent holds a COPY of the key, so every cryptographic check
// answers "same identity" — correctly, and uselessly. Challenge-response settles
// *are you 1234*. It cannot settle *are you the only 1234*, because that is a
// fact about PROCESSES, and no key knows about processes.
//
// The discriminator is an instance id minted at process start and held only in
// memory. Two connections of one process present the same one; a restarted or
// cloned process re-runs startup and mints a new one.
// ─────────────────────────────────────────────────────────────────────────────
//
// ⚠️ THE CLAIM IS ATTACHED TO AUTHENTICATION, NOT TO CONNECTION, AND THAT IS
// THE WHOLE REASON MULTI-CONNECTION SURVIVES. A CLI and an MCP adapter attached
// at once is the normal case — `websocket.ts` keeps `entityId -> Set<sessionId>`
// and fans pushes to all of them. Same instance id is a CONNECTION; a different
// one is a CLAIM.

import type { DatabaseContext } from '../../db/transaction';
import type { EntityId } from '../../types';

export interface ClaimOutcome {
  /**
   * The fencing token. Advances ONLY when a different instance takes the
   * identity, so a holder can distinguish "I am still current" from "someone
   * took this" without asking anyone.
   */
  generation: number;
  /** How many sessions of other instances were ended by this claim. */
  superseded: number;
  /**
   * The session ids that were superseded.
   *
   * ⚠️ THE CALLER MUST CLOSE THESE SOCKETS. Marking the rows ends the REQUEST
   * path only; a WebSocket is validated once at connect and then lives in the
   * manager's in-memory maps, which nothing revalidates. Returning a count
   * instead of the ids is what left an evicted instance still receiving pushes.
   */
  supersededSessionIds: string[];
}

interface ClaimRow {
  generation: number;
  instance_id: string;
}

/**
 * Record that `instanceId` holds `entityId`, superseding any other instance.
 *
 * ⚠️ EVICT-OLD IS THE RULE (CireSnave, 2026-09-08). The common cause of a second
 * instance is a resumed or restarted session whose predecessor is already dead
 * or useless, so the newcomer wins and the old one is told.
 *
 * ⚠️ AND THE WHOLE OPERATION IS ONE TRANSACTION. The claim row and the session
 * deletions must not be separable: a claim written without its evictions leaves
 * two live instances both believing they hold the identity, which is the exact
 * state this exists to end — and it would look like success from both sides.
 */
export function claimIdentity(
  ctx: DatabaseContext,
  entityId: EntityId,
  instanceId: string
): ClaimOutcome {
  return ctx.db.transaction(() => {
    const current = ctx.db
      .prepare('SELECT generation, instance_id FROM entity_claims WHERE entity_id = ?')
      .get(entityId) as ClaimRow | undefined;

    // Same instance re-authenticating: a connection, not a claim. No bump, no
    // eviction — only a refreshed timestamp, so an idle-claim sweep (if one is
    // ever added) does not mistake a busy instance for an abandoned one.
    if (current && current.instance_id === instanceId) {
      ctx.db
        .prepare("UPDATE entity_claims SET claimed_at = datetime('now') WHERE entity_id = ?")
        .run(entityId);
      return { generation: current.generation, superseded: 0, supersededSessionIds: [] };
    }

    const generation = (current?.generation ?? 0) + 1;

    ctx.db
      .prepare(
        `INSERT INTO entity_claims (entity_id, generation, instance_id, claimed_at)
         VALUES (?, ?, ?, datetime('now'))
         ON CONFLICT(entity_id) DO UPDATE SET
           generation = excluded.generation,
           instance_id = excluded.instance_id,
           claimed_at = excluded.claimed_at`
      )
      .run(entityId, generation, instanceId);

    // ⚠️ NO FLAP PROTECTION HERE, AND THIS IS WHERE IT WOULD GO.
    //
    // Two processes that both keep reconnecting will evict each other in turn.
    // The remedy is a minimum hold time before a fresh claim may supersede, and
    // it is NOT IMPLEMENTED — deliberately, with a condition rather than a
    // shrug.
    //
    // THE FLOOR MUST BE MEASURED FROM AN OBSERVED RESTART-TO-RECONNECT INTERVAL,
    // AND FAM HAS NO POPULATION TO MEASURE: no deployment, no fleet, no restart
    // history. A constant chosen now would look principled, be arbitrary, and
    // have nothing recording which.
    //
    // ⚠️ AND DO NOT SUBSTITUTE A PROXY. The claude-peers broker's registration
    // behaviour is a different system with a different restart profile, and a
    // proxy stated as a proxy still becomes the number people quote. A missing
    // guard with a stated reason is auditable; a guard tuned to a foreign
    // workload is not.
    //
    // TRIGGER: set the floor when FAM has real restart data. Tracked as #54, and
    // repeated HERE because the pull request that implements it will close #54 and
    // take the condition with it — a warning about a fix does not survive in the
    // artifact that fix closes.

    // ⚠️ AFTER the claim is written, so a crash between the two leaves the
    // claim ahead of the evictions rather than behind them. An un-evicted old
    // session is a visible inconsistency the next claim repairs; an eviction
    // with no claim behind it is a session destroyed for no recorded reason.
    const supersededSessionIds = ctx.sessions.supersedeOtherInstances(entityId, instanceId);

    return {
      generation,
      superseded: supersededSessionIds.length,
      supersededSessionIds,
    };
  })();
}

/**
 * How a superseded instance finds out.
 *
 * ⚠️ THERE IS NO SECOND NOTIFICATION PATH, DELIBERATELY. Supersession ends the
 * old instance's sessions, so its next authenticated request answers 401 — and
 * the MCP client already classifies 4xx as PERMANENT and fires
 * `onTerminalFailure` (`adapters/mcp/client.ts`), which exists because
 * "between retries" and "finished forever" were previously indistinguishable
 * from outside.
 *
 * ⚠️ AND A SUPERSEDED CLIENT MUST NOT RETRY. An evicted process that reconnects
 * in a backoff loop is the ping-pong failure, where two instances evict each
 * other forever. The existing terminal classification is what prevents it, which
 * is why reusing that seam is the design rather than a convenience.
 */
export const SUPERSESSION_IS_DELIVERED_AS = '401 on the next request, via the existing terminal-failure path';
