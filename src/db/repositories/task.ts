// Task Repository — work with an owner.
//
// Exists so that "nobody is doing this" is a QUERY rather than something a
// coordinator has to remember. A lane killed mid-task leaves work that HAD an
// owner and LOST them, and before this nothing in FAM could see it: queue_empty,
// last_state_change and session liveness all answer "is this AGENT stalled?",
// and an orphaned task is about the WORK.
//
// THE CORE NEVER LEARNS WHAT THE WORK IS. `title` and `ref` are opaque strings —
// "fuel#29" is never parsed here — the same discipline that keeps `mcp.cwd`
// meaningless to the context bag.

import { Database } from 'bun:sqlite';
import { randomUUID } from 'crypto';
import type { AccountId, EntityId } from '../../types';

export type TaskStatus = 'open' | 'done' | 'cancelled';

export interface Task {
  id: string;
  account_id: AccountId;
  owner_entity_id: EntityId | null;
  title: string;
  ref: string | null;
  status: TaskStatus;
  created_by_entity: EntityId | null;
  created_at: string;
  assigned_at: string | null;
  closed_at: string | null;
}

export interface CreateTaskInput {
  title: string;
  owner_entity_id?: EntityId | null;
  ref?: string | null;
  created_by_entity?: EntityId | null;
}

/**
 * Why a piece of open work has nobody on it.
 *
 * KEPT APART DELIBERATELY. "Re-queue it" and "assign it to somebody" are
 * different actions, and collapsing the two causes into one "orphaned" flag
 * would make the list say less than it knows.
 */
export type UnattendedReason = 'unowned' | 'owner_offline';

export interface UnattendedTask {
  task: Task;
  reason: UnattendedReason;
  /**
   * When the owner was last seen, or null when there is no owner.
   *
   * Reported rather than judged: an owner offline for four minutes and one
   * offline for four days are both "not connected", and only the reader knows
   * which matters. Baking a threshold in here would decide that for them.
   */
  owner_last_seen: string | null;
}

export class TaskRepository {
  constructor(private db: Database) {}

  create(accountId: AccountId, input: CreateTaskInput): Task {
    const id = randomUUID();
    const owner = input.owner_entity_id ?? null;

    this.db
      .prepare(
        `INSERT INTO tasks (id, account_id, owner_entity_id, title, ref,
                            created_by_entity, assigned_at)
         VALUES (?, ?, ?, ?, ?, ?, ${owner ? "datetime('now')" : 'NULL'})`
      )
      .run(id, accountId, owner, input.title, input.ref ?? null, input.created_by_entity ?? null);

    return this.getById(id)!;
  }

  getById(id: string): Task | null {
    return (this.db.prepare('SELECT * FROM tasks WHERE id = ?').get(id) as Task | null) ?? null;
  }

  listByAccount(accountId: AccountId, status?: TaskStatus): Task[] {
    const sql = status
      ? 'SELECT * FROM tasks WHERE account_id = ? AND status = ? ORDER BY created_at DESC'
      : 'SELECT * FROM tasks WHERE account_id = ? ORDER BY created_at DESC';
    const rows = status
      ? this.db.prepare(sql).all(accountId, status)
      : this.db.prepare(sql).all(accountId);
    return rows as Task[];
  }

  /** Hand the work to someone, or to nobody by passing null. */
  assign(id: string, ownerEntityId: EntityId | null): void {
    this.db
      .prepare(
        `UPDATE tasks
         SET owner_entity_id = ?,
             assigned_at = CASE WHEN ? IS NULL THEN NULL ELSE datetime('now') END
         WHERE id = ?`
      )
      .run(ownerEntityId, ownerEntityId, id);
  }

  close(id: string, status: Extract<TaskStatus, 'done' | 'cancelled'>): void {
    this.db
      .prepare(`UPDATE tasks SET status = ?, closed_at = datetime('now') WHERE id = ?`)
      .run(status, id);
  }

  /**
   * Open work in this account that nobody is currently on.
   *
   * DERIVED AT READ TIME, never stored. A stored "orphaned" flag goes stale the
   * moment an owner reconnects — the same reason context collisions are
   * computed rather than written.
   *
   * Only OPEN work. Reporting closed tasks would pad the list with things
   * nobody can act on, which trains a reader to skim it — and a list that gets
   * skimmed is how a real orphan is missed.
   *
   * Liveness is connection-derived on purpose. This is the one question where
   * "is the process there" is exactly right: an owner that is not connected is
   * not working, whatever it last declared about itself.
   */
  findUnattended(accountId: AccountId): UnattendedTask[] {
    const rows = this.db
      .prepare(
        `SELECT t.*, e.last_seen AS owner_last_seen,
                (SELECT COUNT(*) FROM sessions s WHERE s.entity_id = t.owner_entity_id
                   AND julianday(s.last_heartbeat) > julianday('now', '-60 seconds')
                ) AS live_sessions
         FROM tasks t
         LEFT JOIN entities e ON e.id = t.owner_entity_id
         WHERE t.account_id = ? AND t.status = 'open'
         ORDER BY t.created_at ASC`
      )
      .all(accountId) as Array<Task & { owner_last_seen: string | null; live_sessions: number }>;

    const out: UnattendedTask[] = [];

    for (const row of rows) {
      const { owner_last_seen, live_sessions, ...task } = row;

      if (task.owner_entity_id === null) {
        out.push({ task: task as Task, reason: 'unowned', owner_last_seen: null });
        continue;
      }
      if (live_sessions === 0) {
        out.push({ task: task as Task, reason: 'owner_offline', owner_last_seen });
      }
    }

    return out;
  }
}
