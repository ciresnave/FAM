// Ruling routes.
//
// The load-bearing one is `/rulings/check`: an entity asks FAM whether its own
// account holds an authority, instead of believing a message that says so. That
// is the whole feature — the relayed claim leaves the trust path, and the
// untrusted channel stops being load-bearing.
//
// Creating is account-scoped and the granter is ALWAYS the authenticated
// account. It is never read from the body, for the reason the entity routes
// never read `entity_id` from a body: a recorder who could name someone else as
// granter would turn this table back into the relayed claim it replaces.

import type { DatabaseContext } from '../../db/transaction';
import type { Route } from './index';
import { requireEntitySession, requireAccountAuth } from '../middleware/auth';
import { NotFoundError, ForbiddenError, ValidationError } from '../../types/errors';

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

export function rulingRoutes(ctx: DatabaseContext): Route[] {
  return [
    // POST /rulings/check
    // "Does <granter> grant MY account <scope>?"
    //
    // Entity session, and the grantee is derived from the caller's own account.
    // A caller may only ask about authority granted TO them: letting anyone ask
    // about any pair would make this a directory of who trusts whom, which is a
    // disclosure nobody asked for and is not needed to act on your own grant.
    {
      method: 'POST',
      pattern: '/rulings/check',
      handler: async (req) => {
        const { entityId, body } = await requireEntitySession(ctx, req);
        const { granter_account_id: granter, scope } = body;

        if (!granter || !scope) {
          throw new ValidationError('granter_account_id and scope are required');
        }

        const caller = ctx.entities.getById(entityId)!;
        const ruling = ctx.rulings.findActive(granter, caller.account_id, scope);

        // Absence is reported as an explicit negative rather than a 404. "No
        // such authority" is an ANSWER to this question, and a caller that
        // cannot distinguish it from a failed lookup is back where it started.
        return json({
          granted: ruling !== null,
          grantee_account_id: caller.account_id,
          ruling: ruling
            ? {
                id: ruling.id,
                granter_account_id: ruling.granter_account_id,
                scope: ruling.scope,
                body: ruling.body,
                issued_at: ruling.issued_at,
                // The note travels WITH its author, always. Separating them is
                // how a derived reading acquires the granter's authority.
                note: ruling.note,
                note_author_entity: ruling.note_author_entity,
              }
            : null,
        });
      },
    },

    // POST /admin/api/rulings
    // Record a ruling. The granter is the authenticated account, full stop.
    {
      method: 'POST',
      pattern: '/admin/api/rulings',
      handler: async (req) => {
        const { accountId, body } = await requireAccountAuth(ctx, req);
        const { grantee_account_id, scope, body: rulingBody, note, recorded_by_entity } = body;

        // A recorder must belong to the granting account, or the attribution on
        // a note would name an entity the granter does not own.
        if (recorded_by_entity) {
          const recorder = ctx.entities.getById(recorded_by_entity);
          if (!recorder || recorder.account_id !== accountId) {
            throw new ForbiddenError('recorded_by_entity must be an entity in your account');
          }
        }

        const ruling = ctx.rulings.create(accountId, {
          grantee_account_id,
          scope,
          body: rulingBody,
          note,
          recorded_by_entity,
        });

        return json({ ruling }, 201);
      },
    },

    // POST /admin/api/rulings/list
    {
      method: 'POST',
      pattern: '/admin/api/rulings/list',
      handler: async (req) => {
        const { accountId, body } = await requireAccountAuth(ctx, req);
        const direction = body?.direction ?? 'given';

        if (!['given', 'received'].includes(direction)) {
          throw new ValidationError('direction must be "given" or "received"');
        }

        const rulings =
          direction === 'given'
            ? ctx.rulings.listByGranter(accountId)
            : ctx.rulings.listForGrantee(accountId);

        return json({ rulings });
      },
    },

    // POST /admin/api/rulings/revoke
    {
      method: 'POST',
      pattern: '/admin/api/rulings/revoke',
      handler: async (req) => {
        const { accountId, body } = await requireAccountAuth(ctx, req);
        const { ruling_id } = body;

        if (!ruling_id) throw new ValidationError('ruling_id is required');

        const ruling = ctx.rulings.getById(ruling_id);
        // Same answer for "not yours" and "does not exist" — the ruling API must
        // not become a probe for what other accounts have granted.
        if (!ruling || ruling.granter_account_id !== accountId) {
          throw new NotFoundError('Ruling you granted', ruling_id);
        }

        ctx.rulings.revoke(ruling_id);
        return json({ ruling: ctx.rulings.getById(ruling_id) });
      },
    },
  ];
}
