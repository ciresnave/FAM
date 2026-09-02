// Message Reference Repository — typed references, opaque to the core.
//
// FAM carries and compares references; it never resolves or interprets one. It
// does not know what `git.ref` means and would accept `weird.tenant_slug` on
// identical terms — the property that keeps this a federation protocol rather
// than a git client, and the same discipline that keeps `mcp.cwd` meaningless
// to the context bag.
//
// The validation rules attach to the MODE, not the KIND. That is what lets the
// core enforce them while staying ignorant: it does not know what a measurement
// is, only that anything claiming to be reproducible must say when, as whom,
// and over what.

import { Database } from 'bun:sqlite';
import { randomUUID } from 'crypto';
import { ValidationError } from '../../types/errors';
import { assertWithinLimit } from '../../types/validation';

/**
 * How a recipient can check a reference.
 *
 *   verifiable    RE-FETCH the thing and compare. It exists or it does not.
 *   reproducible  RE-RUN the observation. This produces a NEW measurement and
 *                 does NOT confirm the old one, because the observation was
 *                 never stored — only the method was.
 *
 * A verifiable reference points at something that exists. A reproducible one
 * points at a computation over a state that no longer exists, so it can resolve
 * perfectly and still be false, and nothing errors.
 */
export type RefMode = 'verifiable' | 'reproducible';

export interface MessageRefInput {
  kind: string;
  mode: RefMode;
  payload: Record<string, string>;
}

export interface MessageRef {
  id: string;
  message_id: number;
  kind: string;
  mode: RefMode;
  payload: Record<string, string>;
  created_at: string;
}

/** Bound on the serialised payload. Big enough for a handful of fields. */
export const REF_PAYLOAD_MAX = 4000;

const MODES: RefMode[] = ['verifiable', 'reproducible'];

export class MessageRefRepository {
  constructor(private db: Database) {}

  attach(messageId: number, input: MessageRefInput): MessageRef {
    this.validate(input);

    const id = randomUUID();
    this.db
      .prepare(
        `INSERT INTO message_refs (id, message_id, kind, mode, payload)
         VALUES (?, ?, ?, ?, ?)`
      )
      .run(id, messageId, input.kind, input.mode, JSON.stringify(input.payload));

    return this.getById(id)!;
  }

  getById(id: string): MessageRef | null {
    const row = this.db.prepare('SELECT * FROM message_refs WHERE id = ?').get(id) as any;
    return row ? this.mapRow(row) : null;
  }

  listForMessage(messageId: number): MessageRef[] {
    const rows = this.db
      .prepare('SELECT * FROM message_refs WHERE message_id = ? ORDER BY created_at ASC')
      .all(messageId) as any[];
    return rows.map(r => this.mapRow(r));
  }

  // --------------------------------------------------------------------------
  // Validation — structure only, never meaning
  // --------------------------------------------------------------------------

  /**
   * Check a reference without storing it.
   *
   * Public so a caller can reject bad input BEFORE committing anything else —
   * validating inside attach() alone meant a send inserted its message row and
   * then threw, leaving a message the caller believed was never sent.
   */
  validate(input: MessageRefInput): void {
    this.assertShape(input);
    this.assertModeRequirements(input);

    const encoded = JSON.stringify(input.payload);
    assertWithinLimit(encoded, REF_PAYLOAD_MAX, {
      unit: 'bytes',
      field: 'Reference payload',
      why:
        'a partial payload would satisfy the mode requirements with the fields that ' +
        'survived and stay silent about the rest.',
    });
  }

  /** Namespaced kind, known mode, string-valued payload. Structure only. */
  private assertShape(input: MessageRefInput): void {
    const { kind, mode, payload } = input;

    // Namespaced, for the reason context keys are: a bare `ref` would be FAM
    // asserting a concept it does not have. Written as prose rather than as an
    // angle-bracket template — a literal that looks like markup is one a static
    // analyser flags and a future reader has to think about.
    const namespaced =
      typeof kind === 'string' && kind.includes('.') && !kind.startsWith('.') && !kind.endsWith('.');
    if (!namespaced) {
      throw new ValidationError(
        `Reference kind "${kind}" is not namespaced. Use a namespace, a dot, then a ` +
          'kind — for example "git.ref". FAM does not interpret the namespace; it ' +
          'exists so the core is never asked to own a concept belonging to an adapter.'
      );
    }

    if (!MODES.includes(mode)) {
      throw new ValidationError(
        `Reference mode must be one of ${MODES.join(', ')}. The mode says how a ` +
          'recipient can CHECK this, and there is no third answer: either they can ' +
          're-fetch the thing, or they can only re-run the observation.'
      );
    }

    if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
      throw new ValidationError('Reference payload must be an object of string fields');
    }

    for (const [key, value] of Object.entries(payload)) {
      if (typeof value !== 'string') {
        throw new ValidationError(
          `Reference payload field "${key}" is ${typeof value}; only strings are stored. ` +
            'The core compares these and never interprets them.'
        );
      }
    }
  }

  /**
   * The requirements that bind to the MODE rather than the kind.
   *
   * Separated because that is the load-bearing idea: the core does not know what
   * a measurement IS, only that anything claiming to be reproducible must say
   * when, as whom, and over what. Keeping it in its own method means the rule
   * can be read without reading the shape checks around it.
   */
  private assertModeRequirements(input: MessageRefInput): void {
    const { mode, payload } = input;

    if (mode === 'verifiable' && !payload.digest) {
      // Without something to compare, the recipient has a name and no way to
      // check they got the thing the sender meant — the exact failure a typed
      // reference replaces.
      throw new ValidationError(
        'A verifiable reference must carry a `digest` the recipient can compare ' +
          'after re-fetching (a commit sha, a content hash, an etag). Without one ' +
          'it is a name, and a name is what "see DESIGN.md" already was.'
      );
    }

    if (mode !== 'reproducible') return;

    const missing = ['construct', 'taken_at', 'taken_as'].filter(f => !payload[f]);
    if (missing.length === 0) return;

    throw new ValidationError(
      `A reproducible reference must carry ${missing.join(', ')}. ` +
        'construct: what the observation ranged over — "1047 characters" is ' +
        'meaningless without it, and correct arithmetic over an unstated subject ' +
        'is the most common way a right number misleads. ' +
        'taken_at: a ref the reader can count forward from, not a wall clock — ' +
        'old and wrong are different facts. ' +
        'taken_as: the identity it was observed under. A GET on a protected branch ' +
        'returns 404 to a non-admin and 404 to an admin with opposite meanings, so ' +
        'after any privilege change a stored absence without this is unverifiable ' +
        'rather than merely stale.'
    );
  }

  private mapRow(row: any): MessageRef {
    // A corrupt payload RAISES rather than degrading to {}.
    //
    // Returning an empty object handed the caller a reference that violates its
    // own mode requirements while looking well-formed — a verifiable reference
    // with no digest, presented as valid. That hides corruption behind a shape
    // the caller trusts, which is the same instinct that made a 201 mean
    // "stored" and read as "delivered".
    //
    // Payloads are only ever written through validate(), so a malformed one
    // means something else went wrong and should be loud.
    let payload: unknown;
    try {
      payload = JSON.parse(row.payload);
    } catch {
      throw new ValidationError(
        `Reference ${row.id} has an unreadable payload. It was written through ` +
          'validation, so this is corruption rather than a bad input, and returning ' +
          'an empty object would present it as a valid reference.'
      );
    }
    if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
      throw new ValidationError(
        `Reference ${row.id} has a payload that is not an object. See above: a ` +
          'reference that cannot satisfy its own mode requirements must not be ' +
          'returned as though it does.'
      );
    }
    return {
      id: row.id,
      message_id: row.message_id,
      kind: row.kind,
      mode: row.mode,
      payload: payload as Record<string, string>,
      created_at: row.created_at,
    };
  }
}
