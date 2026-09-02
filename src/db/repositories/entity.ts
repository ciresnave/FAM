// Entity Repository - CRUD Operations for Entities

import { Database } from 'bun:sqlite';
import { QueueNotEmptyError, ValidationError } from '../../types/errors';
import { assertWithinLimit } from '../../types/validation';

/** Long enough for a sentence or two of intent; short enough to stay scannable. */
export const SUMMARY_MAX_LENGTH = 500;

/** Bound on the serialised context bag. Big enough for a handful of paths. */
export const CONTEXT_MAX_LENGTH = 4000;
import type { Entity, EntityId, AccountId, EntityType, EntityCapabilities } from '../../types';

// ============================================================================
// Entity Repository
// ============================================================================

export class EntityRepository {
  constructor(private db: Database) {}

  // --------------------------------------------------------------------------
  // Create
  // --------------------------------------------------------------------------

  /**
   * Create a new entity.
   */
  create(
    id: EntityId,
    accountId: AccountId,
    type: EntityType,
    publicKey: string,
    displayName?: string,
    capabilities?: Partial<EntityCapabilities>
  ): Entity {
    const defaultCapabilities: EntityCapabilities = {
      can_send: true,
      can_join_channel: true,
      can_create_entities: false,
      can_create_channels: false,
      can_manage_entities: false,
      encrypt_messages: false,
    };

    const finalCapabilities = {
      ...defaultCapabilities,
      ...capabilities,
    };

    const stmt = this.db.prepare(`
      INSERT INTO entities (id, account_id, type, display_name, capabilities, public_key)
      VALUES (?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      accountId,
      type,
      displayName ?? null,
      JSON.stringify(finalCapabilities),
      publicKey
    );

    return this.getById(id)!;
  }

  // --------------------------------------------------------------------------
  // Read
  // --------------------------------------------------------------------------

  /**
   * Get entity by ID.
   */
  getById(id: EntityId): Entity | null {
    const stmt = this.db.prepare(`
      SELECT * FROM entities WHERE id = ?
    `);

    const row = stmt.get(id) as any;
    if (!row) return null;

    return this.mapRowToEntity(row);
  }

  /**
   * Get all entities for an account.
   */
  getByAccountId(accountId: AccountId): Entity[] {
    const stmt = this.db.prepare(`
      SELECT * FROM entities WHERE account_id = ?
    `);

    const rows = stmt.all(accountId) as any[];
    return rows.map(this.mapRowToEntity);
  }

  /**
   * Get all entities.
   */
  getAll(): Entity[] {
    const stmt = this.db.prepare(`
      SELECT * FROM entities
    `);

    const rows = stmt.all() as any[];
    return rows.map(this.mapRowToEntity);
  }

  /**
   * Get the directory for an account: the account's own entities plus
   * entities other accounts have actively granted to it. This is the
   * visibility set for scope:'directory' — cross-account discovery is
   * default-deny, so granted entities are the only foreign ones visible.
   */
  getDirectoryForAccount(accountId: AccountId): Entity[] {
    const stmt = this.db.prepare(`
      SELECT e.* FROM entities e
      WHERE e.account_id = ?
      UNION
      SELECT e.* FROM entities e
      JOIN grants g ON g.entity_id = e.id
      WHERE g.grantee_account_id = ?
      AND g.status = 'active'
      AND (g.expires_at IS NULL OR datetime(g.expires_at) > datetime('now'))
    `);

    const rows = stmt.all(accountId, accountId) as any[];
    return rows.map(this.mapRowToEntity);
  }

  /**
   * Get all online entities.
   */
  getOnline(): Entity[] {
    const stmt = this.db.prepare(`
      SELECT * FROM entities WHERE status = 'online'
    `);

    const rows = stmt.all() as any[];
    return rows.map(this.mapRowToEntity);
  }

  /**
   * Get entities in a channel.
   */
  getByChannelId(channelId: string): Entity[] {
    const stmt = this.db.prepare(`
      SELECT e.* FROM entities e
      JOIN channel_members cm ON e.id = cm.entity_id
      WHERE cm.channel_id = ?
    `);

    const rows = stmt.all(channelId) as any[];
    return rows.map(this.mapRowToEntity);
  }

  // --------------------------------------------------------------------------
  // Update
  // --------------------------------------------------------------------------

  /**
   * Update entity status (connection-derived: online/offline/away).
   */
  updateStatus(id: EntityId, status: 'online' | 'offline' | 'away'): void {
    const stmt = this.db.prepare(`
      UPDATE entities
      SET status = ?, last_seen = datetime('now')
      WHERE id = ?
    `);

    stmt.run(status, id);
  }

  /**
   * Update entity availability (user intent: available/unavailable).
   * Independent of connection status; persists across reconnects.
   */
  updateAvailability(id: EntityId, availability: 'available' | 'unavailable'): void {
    // Stamps last_state_change only when the value actually differs — the
    // column is named for a CHANGE, and re-declaring the same value is not
    // one. If a repeat refreshed it, an agent looping on one state would look
    // perpetually fresh, which is the failure this column exists to avoid.
    const stmt = this.db.prepare(`
      UPDATE entities
      SET availability = ?,
          last_state_change = CASE WHEN availability IS ?
                                   THEN last_state_change
                                   ELSE datetime('now') END
      WHERE id = ?
    `);

    stmt.run(availability, availability, id);
  }

  /**
   * Declare whether this entity's work queue is empty.
   *
   * DECLARED state — only the entity knows, and nothing external can derive it.
   * `null` means never declared, which is deliberately distinct from a declared
   * false: an entity that has never spoken has made no claim, and treating that
   * as "busy" would invent one.
   *
   * READ IT WITH ITS NEIGHBOURS. `queue_empty = 0` alone means working OR dead,
   * and the two are not separable from that column:
   *
   *   queue_empty=0, last_state_change fresh                 -> working, changing
   *   queue_empty=0, last_state_change old, heartbeat fresh  -> one long task
   *   queue_empty=0, last_state_change old, heartbeat stale  -> died mid-task
   *
   * The last two are the pair that matters and the ONLY thing separating them
   * is the heartbeat — so this is a triple, not a pair. A reader who consults
   * queue_empty on its own will call a dead agent busy.
   */
  updateQueueEmpty(id: EntityId, queueEmpty: boolean): void {
    // A declaration the evidence contradicts is REFUSED, not corrected.
    //
    // CireSnave's ruling: "queue_empty = true while the queue is not empty is
    // an error." Silently writing `false` instead would be indistinguishable
    // from success to the caller, who would then believe a declaration that was
    // never accepted — the same shape as a route that answers 200 for work it
    // did not do.
    //
    // Only `true` is checkable. FAM observes undelivered messages and nothing
    // else; it can DISPROVE an empty queue but never prove one, because an
    // agent's internal task list is invisible here. So declaring NOT-empty is
    // always permitted: an agent with an empty inbox may still have plenty to
    // do, and refusing that would be FAM asserting something it cannot see.
    if (queueEmpty) {
      const pending = this.undeliveredCount(id);
      if (pending > 0) {
        throw new QueueNotEmptyError(id, pending);
      }
    }

    const value = queueEmpty ? 1 : 0;
    const stmt = this.db.prepare(`
      UPDATE entities
      SET queue_empty = ?,
          last_state_change = CASE WHEN queue_empty IS ?
                                   THEN last_state_change
                                   ELSE datetime('now') END
      WHERE id = ?
    `);

    stmt.run(value, value, id);
  }

  /**
   * Update entity display name.
   */
  updateDisplayName(id: EntityId, displayName: string): void {
    const stmt = this.db.prepare(`
      UPDATE entities
      SET display_name = ?
      WHERE id = ?
    `);

    stmt.run(displayName, id);
  }

  /**
   * Update entity capabilities.
   */
  updateCapabilities(id: EntityId, capabilities: Partial<EntityCapabilities>): void {
    const current = this.getById(id);
    if (!current) return;

    const updated = {
      ...current.capabilities,
      ...capabilities,
    };

    const stmt = this.db.prepare(`
      UPDATE entities
      SET capabilities = ?
      WHERE id = ?
    `);

    stmt.run(JSON.stringify(updated), id);
  }

  /**
   * Update entity location (for federation).
   */
  updateLocation(id: EntityId, locationServer: string | null): void {
    const stmt = this.db.prepare(`
      UPDATE entities
      SET location_server = ?
      WHERE id = ?
    `);

    stmt.run(locationServer, id);
  }

  // --------------------------------------------------------------------------
  // Delete
  // --------------------------------------------------------------------------

  /**
   * Delete an entity.
   */
  delete(id: EntityId): void {
    const stmt = this.db.prepare(`
      DELETE FROM entities WHERE id = ?
    `);

    stmt.run(id);
  }

  /**
   * Delete all entities for an account.
   */
  deleteByAccountId(accountId: AccountId): void {
    const stmt = this.db.prepare(`
      DELETE FROM entities WHERE account_id = ?
    `);

    stmt.run(accountId);
  }

  /**
   * Set (or clear) this entity's adapter-populated context bag.
   *
   * OPAQUE TO THE CORE. A map of namespaced keys to strings; nothing here
   * parses a value or knows what any key means. Keys must contain a namespace
   * separator, because a bare `cwd` would be FAM claiming a concept of a
   * working directory — which is exactly what does not belong in a federation
   * protocol. `mcp.cwd` belongs to the MCP adapter and stays its business.
   */
  updateContext(id: EntityId, context: Record<string, string> | null): void {
    if (context === null) {
      this.db.prepare('UPDATE entities SET context = NULL WHERE id = ?').run(id);
      return;
    }

    for (const [key, value] of Object.entries(context)) {
      if (!key.includes('.') || key.startsWith('.') || key.endsWith('.')) {
        throw new ValidationError(
          `Context key "${key}" is not namespaced. Use "<adapter>.<key>", e.g. ` +
            '"mcp.cwd". An un-namespaced key would make this a claim about a ' +
            'concept FAM does not have.'
        );
      }
      if (typeof value !== 'string') {
        throw new ValidationError(
          `Context value for "${key}" is ${typeof value}; only strings are stored. ` +
            'The core compares these for equality and never interprets them.'
        );
      }
    }

    const encoded = JSON.stringify(context);
    // BYTES, via the one helper. This counted JavaScript characters while
    // reporting bytes — the identical defect found in message references during
    // review, fixed there and left standing here, which is what having two
    // copies of a rule means. A non-ASCII path passed a bound it exceeded.
    assertWithinLimit(encoded, CONTEXT_MAX_LENGTH, {
      unit: 'bytes',
      field: 'Context bag',
      why: 'a partial bag would collide on the keys that survived and stay silent about the rest.',
    });

    this.db.prepare('UPDATE entities SET context = ? WHERE id = ?').run(encoded, id);
  }

  /**
   * Find context values shared by two or more entities in ONE account.
   *
   * Pure equality over opaque strings — this would report a collision on any
   * key at all, which is the property that keeps filesystem knowledge out of
   * the core.
   *
   * SCOPED TO ONE ACCOUNT deliberately. A collision between two of your own
   * sessions is operationally useful; telling you that a stranger's session
   * runs from the same path is a disclosure nobody asked for, and the harm this
   * exists to fix was always same-operator.
   */
  findContextCollisions(accountId: AccountId): Array<{
    key: string;
    value: string;
    entity_ids: EntityId[];
  }> {
    const rows = this.db
      .prepare('SELECT id, context FROM entities WHERE account_id = ? AND context IS NOT NULL')
      .all(accountId) as Array<{ id: string; context: string }>;

    const seen = new Map<string, { key: string; value: string; entity_ids: string[] }>();

    for (const row of rows) {
      let bag: Record<string, string>;
      try {
        bag = JSON.parse(row.context);
      } catch {
        continue; // An unreadable bag is not a collision.
      }
      for (const [key, value] of Object.entries(bag)) {
        if (typeof value !== 'string' || value === '') continue;
        const composite = `${key} ${value}`;
        const entry = seen.get(composite) ?? { key, value, entity_ids: [] };
        entry.entity_ids.push(row.id);
        seen.set(composite, entry);
      }
    }

    return [...seen.values()].filter(e => e.entity_ids.length > 1);
  }

  /**
   * Set (or clear) this entity's free-text summary of what it is doing.
   *
   * `null` or whitespace clears it, and clears the stamp with it — a stamp
   * without a summary renders an age for nothing.
   *
   * THE STAMP IS REFRESHED ON EVERY ASSERTION, including a repeat of the same
   * text. That is deliberately the OPPOSITE of `last_state_change`, which
   * records a change and ignores repeats. Staleness asks when someone last
   * vouched for these words; saying them again is vouching, and "still true"
   * is new information about an old sentence.
   *
   * It is emphatically not `last_seen`. A heartbeat proves a process is alive
   * and says nothing about whether its stated intent is current.
   */
  updateSummary(id: EntityId, summary: string | null): void {
    const trimmed = summary?.trim() ?? '';

    // CHARACTERS, deliberately: this is a readability bound ("a sentence or
    // two"), not a storage one, and a 500-character summary reads the same in
    // any script. The unit is stated at the call site so the message cannot
    // drift from the count.
    assertWithinLimit(trimmed, SUMMARY_MAX_LENGTH, {
      unit: 'characters',
      field: 'Summary',
      why: 'a cut-off summary is a claim the entity did not make.',
    });

    if (trimmed === '') {
      this.db
        .prepare('UPDATE entities SET summary = NULL, summary_set_at = NULL WHERE id = ?')
        .run(id);
      return;
    }

    this.db
      .prepare(
        `UPDATE entities SET summary = ?, summary_set_at = datetime('now') WHERE id = ?`
      )
      .run(trimmed, id);
  }

  /**
   * Recompute `queue_empty` from the queue FAM can actually see.
   *
   * An OPERATION, not a setter: the caller supplies no value, because a route
   * that accepts a boolean will eventually be sent one, and this exists
   * precisely so that an account holder cannot assert a queue state on their
   * entity's behalf.
   *
   * A CORRECTION rather than a recompute, because the evidence is one-sided:
   *
   *   undelivered > 0  -> work is definitely pending: overwrite with `false`.
   *   undelivered = 0  -> proves nothing about internal work: LEAVE IT ALONE.
   *
   * Asserting `true` on an empty inbox would be FAM inventing a declaration on
   * the entity's behalf, which is what the nullable column exists to prevent.
   * Returns what it observed so the caller learns something even when nothing
   * changed.
   */
  rederiveQueueEmpty(id: EntityId): {
    queue_empty: boolean | null;
    undelivered: number;
    corrected: boolean;
  } {
    const undelivered = this.undeliveredCount(id);
    const before = this.getById(id)?.queue_empty ?? null;

    if (undelivered === 0) {
      return { queue_empty: before, undelivered, corrected: false };
    }

    const corrected = before !== false;
    if (corrected) {
      this.db
        .prepare(
          `UPDATE entities
           SET queue_empty = 0, last_state_change = datetime('now')
           WHERE id = ?`
        )
        .run(id);
    }

    return { queue_empty: false, undelivered, corrected };
  }

  /** Messages fanned out to this entity and not yet acknowledged. */
  private undeliveredCount(id: EntityId): number {
    const row = this.db
      .prepare(
        `SELECT COUNT(*) as count FROM message_deliveries
         WHERE recipient_entity_id = ? AND delivered = 0`
      )
      .get(id) as { count: number };
    return row.count;
  }

  // --------------------------------------------------------------------------
  // Encryption keys (X25519, for sealed messages)
  // --------------------------------------------------------------------------

  /**
   * Record an entity's X25519 public key, so others can seal messages to it.
   *
   * SEPARATE FROM `public_key`, which is the Ed25519 identity key and is set at
   * creation. Ed25519 signs and cannot do ECDH; reusing it would produce
   * ciphertext the recipient can never open, because an Ed25519 public key
   * imports as X25519 and derives 32 plausible bytes while its own private half
   * is refused. See `src/crypto/keys.ts`.
   *
   * FAM CANNOT GENERATE THIS ON THE ENTITY'S BEHALF. The private half belongs
   * to the entity; a server that made the pair could read the mail, which is
   * the property sealing exists to remove. So the column stays NULL until an
   * entity supplies one, and NULL means "cannot receive sealed messages yet".
   */
  setEncryptionKey(id: EntityId, publicKeyBase64: string): void {
    // Size is checked HERE rather than at the crypto call, because a key stored
    // at the wrong length fails much later, inside someone else's send, on a
    // message that is already gone. X25519 public keys are exactly 32 bytes.
    let decoded: Buffer;
    try {
      decoded = Buffer.from(publicKeyBase64, 'base64');
    } catch {
      throw new ValidationError('Encryption public key must be base64.');
    }

    // Buffer.from is permissive: it skips characters outside the base64
    // alphabet rather than throwing, so garbage decodes to something short
    // instead of failing. Re-encoding and comparing is what actually detects
    // it — the length check below would pass for a long enough string of
    // punctuation.
    if (decoded.toString('base64').replace(/=+$/, '') !== publicKeyBase64.replace(/=+$/, '')) {
      throw new ValidationError('Encryption public key must be valid base64.');
    }

    if (decoded.length !== 32) {
      throw new ValidationError(
        `Encryption public key must be 32 bytes (X25519); got ${decoded.length}.`
      );
    }

    this.db
      .prepare('UPDATE entities SET encryption_public_key = ? WHERE id = ?')
      .run(publicKeyBase64, id);
  }

  /** The stored X25519 public key, or null if the entity has never supplied one. */
  getEncryptionKey(id: EntityId): string | null {
    const row = this.db
      .prepare('SELECT encryption_public_key FROM entities WHERE id = ?')
      .get(id) as { encryption_public_key: string | null } | undefined;

    return row?.encryption_public_key ?? null;
  }

  /**
   * Can a message to this entity be sealed?
   *
   * A QUESTION WITH AN ANSWER, rather than a null check repeated at every call
   * site. The point is that a sender must HAVE an answer before it can choose a
   * path, so falling back to unsealed is a decision made somewhere rather than
   * a default that happens everywhere. "Encrypted unless it wasn't" reads as
   * "encrypted" at every site that does not look.
   *
   * A missing entity answers `false`, the same as one with no key. A caller
   * that could tell those apart would hold an existence oracle for entities in
   * other accounts, which the rest of this codebase deliberately refuses.
   */
  canReceiveSealed(id: EntityId): boolean {
    return this.getEncryptionKey(id) !== null;
  }

  // --------------------------------------------------------------------------
  // Helpers
  // --------------------------------------------------------------------------

  private mapRowToEntity(row: any): Entity {
    return {
      id: row.id,
      account_id: row.account_id,
      type: row.type,
      display_name: row.display_name,
      capabilities: JSON.parse(row.capabilities || '{}'),
      location_server: row.location_server,
      public_key: row.public_key,
      status: row.status || 'offline',
      availability: row.availability || 'available',
      // NULL is preserved as null, not coerced to false. "never declared" and
      // "declared not-empty" are different claims, and this mapper is the one
      // place every reader passes through — `!!row.queue_empty` here would
      // erase the distinction for all of them at once.
      queue_empty:
        row.queue_empty === null || row.queue_empty === undefined
          ? null
          : Boolean(row.queue_empty),
      last_state_change: row.last_state_change ?? null,
      summary: row.summary ?? null,
      summary_set_at: row.summary_set_at ?? null,
      context: (() => {
        if (!row.context) return null;
        try {
          return JSON.parse(row.context) as Record<string, string>;
        } catch {
          // A bag that will not parse is reported as absent rather than
          // crashing every read of the entity.
          return null;
        }
      })(),
      created_at: row.created_at,
      last_seen: row.last_seen,
    };
  }
}
