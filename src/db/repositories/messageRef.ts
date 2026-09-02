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

  private validate(input: MessageRefInput): void {
    const { kind, mode, payload } = input;

    // Namespaced, for the reason context keys are: a bare `ref` would be FAM
    // asserting a concept it does not have.
    if (typeof kind !== 'string' || !kind.includes('.') || kind.startsWith('.') || kind.endsWith('.')) {
      throw new ValidationError(
        `Reference kind "${kind}" is not namespaced. Use "<namespace>.<kind>", ` +
          'e.g. "git.ref". FAM does not interpret the namespace; it exists so the ' +
          'core is never asked to own a concept that belongs to an adapter.'
      );
    }

    if (!MODES.includes(mode)) {
      throw new ValidationError(
        `Reference mode must be one of ${MODES.join(', ')}. ` +
          'The mode says how a recipient can CHECK this, and there is no third answer: ' +
          'either they can re-fetch the thing, or they can only re-run the observation.'
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

    // ---- Requirements bind to the MODE, not the kind ----

    if (mode === 'verifiable') {
      // Without something to compare, the recipient has a name and no way to
      // check they got the thing the sender meant — the exact failure a typed
      // reference replaces.
      if (!payload.digest) {
        throw new ValidationError(
          'A verifiable reference must carry a `digest` the recipient can compare ' +
            'after re-fetching (a commit sha, a content hash, an etag). Without one ' +
            'it is a name, and a name is what "see DESIGN.md" already was.'
        );
      }
    }

    if (mode === 'reproducible') {
      const missing = ['construct', 'taken_at', 'taken_as'].filter(f => !payload[f]);
      if (missing.length > 0) {
        throw new ValidationError(
          `A reproducible reference must carry ${missing.join(', ')}. ` +
            'construct: what the observation ranged over — "1047 characters" is ' +
            'meaningless without it, and correct arithmetic over an unstated subject ' +
            'is the most common way a right number misleads. ' +
            'taken_at: a ref the reader can count forward from, not a wall clock — ' +
            'old and wrong are different facts. ' +
            'taken_as: the identity it was observed under. GET on a protected branch ' +
            'returns 404 to a non-admin and 404 to an admin with opposite meanings, ' +
            'so after any privilege change a stored absence without this is ' +
            'unverifiable rather than merely stale.'
        );
      }
    }

    const encoded = JSON.stringify(payload);
    if (encoded.length > REF_PAYLOAD_MAX) {
      throw new ValidationError(
        `Reference payload is ${encoded.length} bytes; the limit is ${REF_PAYLOAD_MAX}. ` +
          'Refused rather than trimmed: a partial payload would satisfy the mode ' +
          'requirements with fields that survived and stay silent about the rest.'
      );
    }
  }

  private mapRow(row: any): MessageRef {
    let payload: Record<string, string> = {};
    try {
      payload = JSON.parse(row.payload);
    } catch {
      // An unreadable payload is reported as empty rather than crashing every
      // read of the message it hangs off.
      payload = {};
    }
    return {
      id: row.id,
      message_id: row.message_id,
      kind: row.kind,
      mode: row.mode,
      payload,
      created_at: row.created_at,
    };
  }
}
