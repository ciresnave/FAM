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
import { validateAccountToken, extractBearerToken } from '../middleware/auth';

// ============================================================================
// Helpers
// ============================================================================

/**
 * Parse the request body once and validate the account token (from body or
 * Authorization header). Returns the authenticated account and parsed body —
 * avoids re-reading the request body in each handler.
 */
async function requireAccount(
  ctx: DatabaseContext,
  req: Request
): Promise<{ accountId: string; body: any }> {
  const body = await req.json().catch(() => ({})) as any;
  const token = extractBearerToken(req) ?? body.account_token;
  const accountId = await validateAccountToken(ctx, token);
  return { accountId, body };
}

// ============================================================================
// Admin Routes
// ============================================================================

export function adminRoutes(ctx: DatabaseContext): Route[] {
  return [
    // POST /admin/api/grants
    // Grant another account access to one of my entities.
    // The authenticated account is the GRANTOR (shares its entity);
    // grantee_account_id is the account receiving access.
    {
      method: 'POST',
      pattern: '/admin/api/grants',
      handler: async (req) => {
        const { accountId: grantorAccountId, body } = await requireAccount(ctx, req);
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
        const entity = ctx.entities.getById(entityId);
        if (!entity) {
          throw new NotFoundError('Entity', entityId);
        }
        if (entity.account_id !== grantorAccountId) {
          throw new ForbiddenError('Entity does not belong to your account');
        }

        // Grantee account must exist
        if (!ctx.accounts.exists(granteeAccountId)) {
          throw new NotFoundError('Account', granteeAccountId);
        }

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
        const { accountId, body } = await requireAccount(ctx, req);
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
        const { accountId, body } = await requireAccount(ctx, req);
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
        const { accountId, body } = await requireAccount(ctx, req);
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
          const target = ctx.entities.getById(target_entity_id);
          if (!target) {
            throw new NotFoundError('Entity', target_entity_id);
          }
          if (target.account_id !== accountId) {
            throw new ForbiddenError('Target entity does not belong to your account');
          }
        }

        // Source validation: entity or account must exist
        if (source_type === 'entity') {
          if (!source_entity_id) {
            throw new ValidationError('source_entity_id required when source_type is "entity"');
          }
          validateEntityId(source_entity_id);
          if (!ctx.entities.getById(source_entity_id)) {
            throw new NotFoundError('Entity', source_entity_id);
          }
        } else {
          if (!source_account_id) {
            throw new ValidationError('source_account_id required when source_type is "account"');
          }
          validateAccountId(source_account_id);
          if (!ctx.accounts.exists(source_account_id)) {
            throw new NotFoundError('Account', source_account_id);
          }
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
        } catch {
          throw new ConflictError('Rule for this (target, source) tuple already exists — delete it first if you want to change its action');
        }

        return new Response(
          JSON.stringify({ rule }),
          { status: 201, headers: { 'Content-Type': 'application/json' } }
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
        const { accountId } = await requireAccount(ctx, req);

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
          created_at: entity.created_at,
          relationship: entity.account_id === accountId ? 'owned' : 'granted',
        }));

        return new Response(
          JSON.stringify({ entities: annotated, total: annotated.length }),
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
        const { accountId } = await requireAccount(ctx, req);
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
        const { accountId, body } = await requireAccount(ctx, req);
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
