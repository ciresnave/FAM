// Permission Checker - Messaging Authorization
//
// Policy:
// - Same-account DMs: default-ALLOW. An explicit deny rule on the target's
//   account (matching the sender entity or the sender's whole account)
//   revokes access; a more specific allow rule overrides a broader deny.
// - Cross-account DMs: default-DENY. Requires an active grant from the
//   TARGET's account (grantor) to the SENDER's account (grantee) for the
//   target entity. Explicit deny rules override grants. Grant capabilities
//   can further restrict (capabilities.can_send === false blocks).
// - Channel messages: membership implies allow (joining a channel opts into
//   messages from its members). Explicit deny rules on a member's account
//   still filter pushes to that member (see isDeniedByRules).
//
// Rule specificity (most specific wins; ties are impossible — identical
// specificity implies an identical unique tuple):
//   1. target=entity, source=entity   (score 3)
//   2. target=entity, source=account  (score 2)
//   3. target=all,    source=entity   (score 1)
//   4. target=all,    source=account  (score 0)

import type { DatabaseContext } from '../../db/transaction';
import type { EntityId, Entity, PermissionRule } from '../../types';

// ============================================================================
// Permission Checker
// ============================================================================

export class PermissionChecker {
  constructor(private ctx: DatabaseContext) {}

  /**
   * Can source send a DIRECT message to target?
   * Enforces grants (cross-account) + deny/allow rules.
   */
  canDirectMessage(source: Entity, target: Entity): boolean {
    if (source.account_id === target.account_id) {
      // Same account: default-allow unless rules say deny
      return !this.bestRuleDenies(source, target);
    }

    // Cross-account: grant required (target's account shares the target entity
    // with the source's account)
    const grant = this.ctx.grants.findActive(
      target.account_id,
      source.account_id,
      target.id
    );
    if (!grant) return false;
    if (grant.capabilities.can_send === false) return false;

    // Explicit deny rules override grants
    return !this.bestRuleDenies(source, target);
  }

  /**
   * Do explicit rules (ignoring grants) deny source → target?
   * Used for channel push filtering, where membership is the grant:
   * a member's account can still revoke pushes from a specific sender.
   */
  isDeniedByRules(source: Entity, target: Entity): boolean {
    return this.bestRuleDenies(source, target);
  }

  // --------------------------------------------------------------------------
  // Rule Resolution
  // --------------------------------------------------------------------------

  private bestRuleDenies(source: Entity, target: Entity): boolean {
    const best = this.findBestRule(source, target);
    return best !== null && best.action === 'deny';
  }

  /**
   * Find the most specific rule on the target's account matching this
   * (source, target) pair. Returns null when no rule matches.
   */
  private findBestRule(source: Entity, target: Entity): PermissionRule | null {
    const rules = this.ctx.permissions.listByAccount(target.account_id);

    let best: PermissionRule | null = null;
    let bestScore = -1;

    for (const rule of rules) {
      if (!this.ruleMatches(rule, source, target)) continue;

      const score = this.specificity(rule);
      if (score > bestScore) {
        best = rule;
        bestScore = score;
      }
    }

    return best;
  }

  private ruleMatches(rule: PermissionRule, source: Entity, target: Entity): boolean {
    // Target side: protect this specific entity, or all of the account's entities
    if (rule.target_type === 'entity') {
      if (rule.target_entity_id !== target.id) return false;
    }

    // Source side: this specific entity, or the source's whole account
    if (rule.source_type === 'entity') {
      if (rule.source_entity_id !== source.id) return false;
    } else {
      if (rule.source_account_id !== source.account_id) return false;
    }

    return true;
  }

  private specificity(rule: PermissionRule): number {
    return (rule.target_type === 'entity' ? 2 : 0) + (rule.source_type === 'entity' ? 1 : 0);
  }
}
