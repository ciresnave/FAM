// Admin Routes for FAM Server
//
// Account-scoped management of grants and permission rules.
// Auth: account bearer token (same as /accounts/* routes). Phase 4 (admin
// website) will add cookie-based browser sessions on these same paths.

import type { DatabaseContext } from '../../db/transaction';
import type { Route } from './index';
import {
  NotFoundError,
  ForbiddenError,
  ConflictError,
  ValidationError,
} from '../../types/errors';
import { validateEntityId, validateAccountId } from '../../types/validation';
import { requireAccountAuth } from '../middleware/auth';
import type { WebSocketManager } from '../websocket';

// ============================================================================
// Helpers
// ============================================================================

// ============================================================================
// Admin Routes
// ============================================================================

export function adminRoutes(
  ctx: DatabaseContext,
  wsManager: WebSocketManager
): Route[] {
  return [
    // POST /admin/api/grants
    // Grant another account access to one of my entities.
    // The authenticated account is the GRANTOR (shares its entity);
    // grantee_account_id is the account receiving access.
    {
      method: 'POST',
      pattern: '/admin/api/grants',
      handler: async (req) => {
        const { accountId: grantorAccountId, body } = await requireAccountAuth(ctx, req);
        const { grantee_account_id: granteeAccountId, entity_id: entityId, capabilities, expires_at } = body;

        if (!granteeAccountId || !entityId) {
          return new Response(
            JSON.stringify({ error: 'Missing grantee_account_id or entity_id' }),
            { status: 400, headers: { 'Content-Type': 'application/json' } }
          );
        }

        validateAccountId(granteeAccountId);
        validateEntityId(entityId);

        if (granteeAccountId === grantorAccountId) {
          throw new ValidationError('Cannot grant to your own account');
        }

        // Entity must exist and belong to the granting account
        // One answer for "does not exist" and "is not yours". You can only
        // grant your own entity, so the distinction serves no caller — and a
        // caller who can tell them apart can enumerate every entity id on the
        // server by probing, which is exactly what the directory-scoping ruling
        // forbids.
        const entity = ctx.entities.getById(entityId);
        if (!entity || entity.account_id !== grantorAccountId) {
          throw new NotFoundError('Entity in your account', entityId);
        }

        // The grantee account deliberately need NOT exist.
        //
        // Ruled by CireSnave: "account A should be able to set up grants and
        // rules for agents that account B hasn't gotten around to creating
        // yet. One shouldn't be forced to wait on the other." Migration v10
        // dropped the foreign key for it; this check was the other half, and
        // while it stood the database permitted a pending grant and the API
        // went on refusing one.
        //
        // It was also an account-existence oracle: 201 when the address had an
        // account and 404 when it did not, testable one address at a time by
        // anyone with an account of their own.

        // No duplicate grant for the same tuple
        if (ctx.grants.findAny(grantorAccountId, granteeAccountId, entityId)) {
          throw new ConflictError('Grant already exists for this account/entity pair (revoke it first)');
        }

        if (capabilities !== undefined && (typeof capabilities !== 'object' || Array.isArray(capabilities))) {
          throw new ValidationError('capabilities must be an object, e.g. {"can_send": true}');
        }

        const grant = ctx.grants.create(
          grantorAccountId,
          granteeAccountId,
          entityId,
          capabilities ?? {},
          expires_at ?? null
        );

        return new Response(
          JSON.stringify({ grant }),
          { status: 201, headers: { 'Content-Type': 'application/json' } }
        );
      },
    },

    // POST /admin/api/grants/list
    // List grants given (direction=given) or received (direction=received)
    {
      method: 'POST',
      pattern: '/admin/api/grants/list',
      handler: async (req) => {
        const { accountId, body } = await requireAccountAuth(ctx, req);
        const direction = body.direction ?? 'given';

        if (!['given', 'received'].includes(direction)) {
          throw new ValidationError('direction must be "given" or "received"');
        }

        const grants = direction === 'given'
          ? ctx.grants.listByGrantor(accountId)
          : ctx.grants.listByGrantee(accountId);

        return new Response(
          JSON.stringify({ grants }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      },
    },

    // POST /admin/api/grants/revoke
    // Revoke a grant I gave
    {
      method: 'POST',
      pattern: '/admin/api/grants/revoke',
      handler: async (req) => {
        const { accountId, body } = await requireAccountAuth(ctx, req);
        const { grant_id: grantId } = body;

        if (!grantId) {
          return new Response(
            JSON.stringify({ error: 'Missing grant_id' }),
            { status: 400, headers: { 'Content-Type': 'application/json' } }
          );
        }

        const grant = ctx.grants.getById(grantId);
        if (!grant) {
          throw new NotFoundError('Grant', grantId);
        }
        if (grant.grantor_account_id !== accountId) {
          throw new ForbiddenError('Only the grantor can revoke this grant');
        }

        ctx.grants.revoke(grantId);

        return new Response(
          JSON.stringify({ ok: true }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      },
    },

    // POST /admin/api/permissions
    // Add an allow/deny rule to my account's permission matrix
    {
      method: 'POST',
      pattern: '/admin/api/permissions',
      handler: async (req) => {
        const { accountId, body } = await requireAccountAuth(ctx, req);
        const {
          target_type, target_entity_id,
          source_type, source_entity_id, source_account_id,
          action,
        } = body;

        if (!target_type || !source_type || !action) {
          return new Response(
            JSON.stringify({ error: 'Missing target_type, source_type, or action' }),
            { status: 400, headers: { 'Content-Type': 'application/json' } }
          );
        }

        if (!['entity', 'all'].includes(target_type)) {
          throw new ValidationError('target_type must be "entity" or "all"');
        }
        if (!['entity', 'account'].includes(source_type)) {
          throw new ValidationError('source_type must be "entity" or "account"');
        }
        if (!['allow', 'deny'].includes(action)) {
          throw new ValidationError('action must be "allow" or "deny"');
        }

        // target_entity_id is meaningless (and ambiguous) for all-target rules
        if (target_type === 'all' && target_entity_id != null) {
          throw new ValidationError('target_entity_id must not be set when target_type is "all"');
        }

        // Target validation: entity targets must belong to my account
        if (target_type === 'entity') {
          if (!target_entity_id) {
            throw new ValidationError('target_entity_id required when target_type is "entity"');
          }
          validateEntityId(target_entity_id);
          // Same collapse as grants: the target is always one of your own.
          const target = ctx.entities.getById(target_entity_id);
          if (!target || target.account_id !== accountId) {
            throw new NotFoundError('Entity in your account', target_entity_id);
          }
        }

        // Source validation: entity or account must exist
        if (source_type === 'entity') {
          if (!source_entity_id) {
            throw new ValidationError('source_entity_id required when source_type is "entity"');
          }
          validateEntityId(source_entity_id);
          // NOTE: this check does not create the enumeration oracle, it only
          // reports it clearly. `permissions.source_entity_id` carries a
          // FOREIGN KEY, so removing this check does not let a rule name a
          // nonexistent subject — the insert fails at the database instead and
          // surfaces as a confusing 409. Closing the oracle requires dropping
          // that FK, which is a migration and a design decision. See ROADMAP.
          if (!ctx.entities.getById(source_entity_id)) {
            throw new NotFoundError('Entity', source_entity_id);
          }
        } else {
          if (!source_account_id) {
            throw new ValidationError('source_account_id required when source_type is "account"');
          }
          validateAccountId(source_account_id);
          // Deliberately NOT checked for existence — same ruling as grants
          // above. You may write a rule about an account before it exists, and
          // the comment that used to sit here ("FK-enforced regardless") went
          // stale when migration v10 dropped that key.
        }

        let rule;
        try {
          rule = ctx.permissions.create({
            account_id: accountId,
            target_type,
            target_entity_id: target_entity_id ?? null,
            source_type,
            source_entity_id: source_entity_id ?? null,
            source_account_id: source_account_id ?? null,
            action,
          });
        } catch (e) {
          // Only a genuine duplicate is a conflict. This used to catch every
          // error and report 409, which turned a foreign-key violation into
          // "rule already exists" — and made a fix that did not work look like
          // one that did.
          if (e instanceof Error && e.message === 'conflict') {
            throw new ConflictError('Rule for this (target, source) tuple already exists — delete it first if you want to change its action');
          }
          throw e;
        }

        return new Response(
          JSON.stringify({ rule }),
          { status: 201, headers: { 'Content-Type': 'application/json' } }
        );
      },
    },

    // POST /admin/api/entities/availability
    // An account holder sets availability on one of THEIR OWN entities.
    //
    // Ruled by CireSnave: "An account holder should be able to change their
    // entity's availability." It is their agent, and one that will not go quiet
    // is worse than one whose owner can quiet it.
    //
    // Goes through wsManager.setAvailability — the same call the entity's own
    // route makes — so this broadcasts and flushes the queued backlog exactly
    // as a self-declaration does. Writing the column directly here would be a
    // second availability path that agrees on the value and differs on the
    // behaviour, which is the harder kind of divergence to notice.
    {
      method: 'POST',
      pattern: '/admin/api/entities/availability',
      handler: async (req) => {
        const { accountId, body } = await requireAccountAuth(ctx, req);
        const { entity_id: entityId, availability } = body;

        if (!entityId || !availability) {
          throw new ValidationError('entity_id and availability are required');
        }
        if (!['available', 'unavailable'].includes(availability)) {
          throw new ValidationError('availability must be "available" or "unavailable"');
        }

        // Same answer for "not yours" and "does not exist" — the console must
        // not become an entity-existence oracle for other accounts.
        const entity = ctx.entities.getById(entityId);
        if (!entity || entity.account_id !== accountId) {
          throw new NotFoundError('Entity in your account', entityId);
        }

        const flushed = await wsManager.setAvailability(entityId, availability);

        return new Response(
          JSON.stringify({ ok: true, entity_id: entityId, availability, messages_pushed: flushed }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      },
    },

    // POST /admin/api/entities/rederive-queue
    // Recompute queue_empty from the queue FAM can observe.
    //
    // Ruled by CireSnave: an account holder may have queue_empty "rederived
    // from the queue itself", but may NOT set it — "queue_empty = true while
    // the queue is not empty is an error."
    //
    // So this takes NO value. A route that accepts a boolean will eventually be
    // sent one, and the whole point is that the account holder cannot assert a
    // queue state on the entity's behalf. It corrects what the evidence
    // contradicts and leaves alone what it merely cannot confirm.
    {
      method: 'POST',
      pattern: '/admin/api/entities/rederive-queue',
      handler: async (req) => {
        const { accountId, body } = await requireAccountAuth(ctx, req);
        const { entity_id: entityId } = body;

        if (!entityId) {
          throw new ValidationError('entity_id is required');
        }
        // Refuse a supplied value rather than ignoring it. Ignoring it would
        // let a caller believe they had set something they had not — the
        // silent-success shape this whole field is designed against.
        if ('queue_empty' in body) {
          throw new ValidationError(
            'queue_empty is not accepted here: this operation DERIVES the value ' +
              'from the queue. Only the entity itself may declare it, via ' +
              'POST /entities/queue-state.'
          );
        }

        const entity = ctx.entities.getById(entityId);
        if (!entity || entity.account_id !== accountId) {
          throw new NotFoundError('Entity in your account', entityId);
        }

        const result = ctx.entities.rederiveQueueEmpty(entityId);

        return new Response(
          JSON.stringify({ ok: true, entity_id: entityId, ...result }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      },
    },

    // POST /admin/api/directory
    // List the account's directory: own entities + entities actively granted
    // to this account by other accounts. Feeds the admin website's directory
    // view (Phase 4).
    {
      method: 'POST',
      pattern: '/admin/api/directory',
      handler: async (req) => {
        const { accountId } = await requireAccountAuth(ctx, req);

        const entities = ctx.entities.getDirectoryForAccount(accountId);

        // Annotate each entity with its relationship to this account so the
        // UI can distinguish owned vs shared
        const annotated = entities.map((entity) => ({
          id: entity.id,
          account_id: entity.account_id,
          type: entity.type,
          display_name: entity.display_name,
          status: entity.status,
          availability: entity.availability,
          // Declared state. Both are reported as stored, including null for
          // queue_empty, which means NEVER DECLARED — a different claim from a
          // declared false, and flattening it here would invent a declaration
          // the entity never made.
          queue_empty: entity.queue_empty ?? null,
          last_state_change: entity.last_state_change ?? null,
          // The summary travels WITH its stamp, always. Rendering one without
          // the other is how a four-day-old statement reads as current.
          summary: entity.summary ?? null,
          summary_set_at: entity.summary_set_at ?? null,
          // OWN entities only. Context describes where a session is running;
          // publishing that to every account you have been granted to is a
          // disclosure nobody asked for, and the harm it exists to fix was
          // always same-operator.
          context: entity.account_id === accountId ? entity.context ?? null : null,
          created_at: entity.created_at,
          relationship: entity.account_id === accountId ? 'owned' : 'granted',
        }));

        // Two of your own sessions sharing a value — the same checkout, say —
        // are mutually invisible without this. Surfaced beside the directory
        // rather than left for a reader to notice by comparing rows.
        const collisions = ctx.entities.findContextCollisions(accountId);

        return new Response(
          JSON.stringify({
            entities: annotated,
            total: annotated.length,
            context_collisions: collisions,
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      },
    },

    // POST /admin/api/permissions/list
    // List my account's permission rules
    {
      method: 'POST',
      pattern: '/admin/api/permissions/list',
      handler: async (req) => {
        const { accountId } = await requireAccountAuth(ctx, req);
        const rules = ctx.permissions.listByAccount(accountId);
        return new Response(
          JSON.stringify({ rules }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      },
    },

    // POST /admin/api/permissions/delete
    // Remove a rule from my account's permission matrix
    {
      method: 'POST',
      pattern: '/admin/api/permissions/delete',
      handler: async (req) => {
        const { accountId, body } = await requireAccountAuth(ctx, req);
        const { permission_id: permissionId } = body;

        if (!permissionId) {
          return new Response(
            JSON.stringify({ error: 'Missing permission_id' }),
            { status: 400, headers: { 'Content-Type': 'application/json' } }
          );
        }

        const deleted = ctx.permissions.deleteForAccount(permissionId, accountId);
        if (!deleted) {
          throw new NotFoundError('Permission rule', permissionId);
        }

        return new Response(
          JSON.stringify({ ok: true }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      },
    },
  ];
}
