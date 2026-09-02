// Task routes — work with an owner.
//
// Entity-scoped: agents create, claim, hand over and close their own work. The
// unattended QUERY is account-scoped and lives with the admin API, because the
// person who needs to see orphaned work is the account holder looking at a
// console, not an agent.
//
// WHO MAY OWN WHAT. Assignment reuses the existing permission check — if you may
// message an entity, you may assign work to it. That is a deliberate reuse
// rather than a second authority model, in a codebase whose rule is that there
// is exactly one of things.
//
// Its limit, stated rather than discovered later: an assignment here is a RECORD
// that somebody owns something, not a command that compels them. If assignment
// ever becomes compelling — auto-dispatch, forced re-queue — it needs its own
// authority, because "may talk to" and "may direct" stop being the same question
// at that point.

import type { DatabaseContext } from '../../db/transaction';
import type { Route } from './index';
import type { PermissionChecker } from '../services/permissionChecker';
import { requireEntitySession } from '../middleware/auth';
import { NotFoundError, ForbiddenError, ValidationError } from '../../types/errors';

const MAX_TITLE = 500;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

export function taskRoutes(ctx: DatabaseContext, permissions: PermissionChecker): Route[] {
  /** The owner must be someone the actor may already talk to. */
  function assertMayOwn(actorId: string, ownerId: string): void {
    const actor = ctx.entities.getById(actorId);
    const owner = ctx.entities.getById(ownerId);
    // One answer for "not permitted" and "no such entity": the task API must not
    // become an entity-existence oracle for other accounts.
    if (!actor || !owner || !permissions.canDirectMessage(actor, owner)) {
      throw new ForbiddenError(
        `Cannot assign to ${ownerId}: you may only assign work to entities you are permitted to message.`
      );
    }
  }

  return [
    // POST /tasks/create
    {
      method: 'POST',
      pattern: '/tasks/create',
      handler: async (req) => {
        const { entityId, body } = await requireEntitySession(ctx, req);
        const { title, ref, owner_entity_id } = body;

        if (typeof title !== 'string' || title.trim() === '') {
          throw new ValidationError('title is required');
        }
        if (title.length > MAX_TITLE) {
          // Refused, not truncated — a cut-off title is a description of work
          // nobody wrote.
          throw new ValidationError(`title is ${title.length} characters; the limit is ${MAX_TITLE}`);
        }

        const actor = ctx.entities.getById(entityId)!;
        if (owner_entity_id != null) assertMayOwn(entityId, owner_entity_id);

        const task = ctx.tasks.create(actor.account_id, {
          title: title.trim(),
          ref: typeof ref === 'string' ? ref : null,
          owner_entity_id: owner_entity_id ?? null,
          created_by_entity: entityId,
        });

        return json({ task }, 201);
      },
    },

    // POST /tasks/assign
    // Hand work over, take it, or set it down (owner_entity_id: null).
    {
      method: 'POST',
      pattern: '/tasks/assign',
      handler: async (req) => {
        const { entityId, body } = await requireEntitySession(ctx, req);
        const { task_id, owner_entity_id } = body;

        if (!task_id) throw new ValidationError('task_id is required');

        const actor = ctx.entities.getById(entityId)!;
        const task = ctx.tasks.getById(task_id);
        if (!task || task.account_id !== actor.account_id) {
          throw new NotFoundError('Task in your account', task_id);
        }

        if (owner_entity_id != null) assertMayOwn(entityId, owner_entity_id);

        ctx.tasks.assign(task_id, owner_entity_id ?? null);
        return json({ task: ctx.tasks.getById(task_id) });
      },
    },

    // POST /tasks/close
    {
      method: 'POST',
      pattern: '/tasks/close',
      handler: async (req) => {
        const { entityId, body } = await requireEntitySession(ctx, req);
        const { task_id, status } = body;

        if (!task_id) throw new ValidationError('task_id is required');
        if (status !== 'done' && status !== 'cancelled') {
          // Explicit only. "Closed" collapses "it is finished" and "it is not
          // happening", and those are different facts about the work.
          throw new ValidationError('status must be "done" or "cancelled"');
        }

        const actor = ctx.entities.getById(entityId)!;
        const task = ctx.tasks.getById(task_id);
        if (!task || task.account_id !== actor.account_id) {
          throw new NotFoundError('Task in your account', task_id);
        }

        ctx.tasks.close(task_id, status);
        return json({ task: ctx.tasks.getById(task_id) });
      },
    },

    // POST /tasks/list
    {
      method: 'POST',
      pattern: '/tasks/list',
      handler: async (req) => {
        const { entityId, body } = await requireEntitySession(ctx, req);
        const actor = ctx.entities.getById(entityId)!;
        const status = body?.status;

        if (status !== undefined && !['open', 'done', 'cancelled'].includes(status)) {
          throw new ValidationError('status must be open, done or cancelled');
        }

        return json({ tasks: ctx.tasks.listByAccount(actor.account_id, status) });
      },
    },
  ];
}
