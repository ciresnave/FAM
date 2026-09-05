// Replay detection for incoming messages.
//
// ─────────────────────────────────────────────────────────────────────────────
// ⚠️ `sequence` HAS BEEN DOCUMENTED AS WHERE REPLAY PROTECTION LIVES AND HAS
// ENFORCED NOTHING.
//
// The envelope calls it "Per-sender counter. Replay protection lives on this."
// Measured before this file existed: zero replay checks anywhere under
// `src/server/`, and the field type-validated as a number and otherwise
// ignored. **A field documented as a security control that is not one is worse
// than an absent field** — an absence prompts a design, a present-but-inert
// field terminates it, because the next reader believes the work is done.
// ─────────────────────────────────────────────────────────────────────────────
//
// ⚠️ WHY NOT MONOTONICITY, WHICH IS THE OBVIOUS CONSTRUCTION.
//
// "Refuse anything not greater than the highest sequence seen from that sender"
// is the textbook answer and it CANNOT BE USED HERE. FAM queues messages for
// offline recipients and pushes the backlog on reconnect, so a legitimate
// message routinely arrives after a higher-numbered one. Monotonicity would
// reject real mail, and the rejection would look exactly like catching an
// attack — the worst possible failure, because it manufactures evidence of a
// threat that is not there.
//
// ⚠️ WHAT THIS DOES INSTEAD: exact duplicate detection inside a bounded window.
// A (sender, sequence) pair seen before is a replay. Out-of-order delivery is
// fine. A sender whose clock steps backwards does not produce false positives,
// because nothing here compares magnitudes.
//
// ⚠️ AND WHAT IT DOES NOT COVER, STATED BECAUSE A BOUNDED GUARANTEE IN CODE IS
// A DESIGN AND THE SAME GUARANTEE UNSTATED IS A CLAIM:
//
//   - A replay AFTER the window lapses is accepted. The store is pruned by the
//     same window, so the entry is no longer there to match. This is a bound,
//     not a fix; the alternative is a store that grows forever.
//   - Clock skew between sender and recipient eats into the window from both
//     ends. The window is deliberately generous for that reason.
//   - A recipient with no store yet — a fresh install, a cleared file — accepts
//     everything once. Trust-on-first-use, in a second place, with the same
//     honest bound.
//   - It says nothing about WHO sent a message. That is the voucher chain's
//     job, and the two are independent: a replayed message is one that was
//     genuinely sent, once.
//
// The upgrade path is the same one the anchor has: an out-of-band exchange —
// here, a durable per-sender counter agreed by both sides — which removes the
// window rather than widening it. Not built.

export interface SeenMessage {
  sender: string;
  sequence: number;
}

export interface IncomingIdentity {
  sender: string;
  sequence: number;
  /** ISO-8601, as stamped by the sender. */
  sentAt: string;
}

export interface ReplayOptions {
  now: Date;
  /** How far either side of `now` a message may be stamped. */
  windowMs: number;
}

export type ReplayVerdict =
  | { kind: 'fresh' }
  | { kind: 'replay'; reason: string }
  /** Too old, too far ahead, or unreadable — all "not in the window I check". */
  | { kind: 'outside-window'; reason: string };

export function checkReplay(
  seen: ReadonlyArray<SeenMessage>,
  message: IncomingIdentity,
  opts: ReplayOptions
): ReplayVerdict {
  const stamped = Date.parse(message.sentAt);

  // ⚠️ NaN FAILS CLOSED, EXPLICITLY. Every comparison with NaN is false, so a
  // window check written as `if (age > window) refuse` passes an unparseable
  // timestamp straight through. That exact fail-open has already been found
  // once in this codebase, in the voucher expiry check — the same shape, in a
  // different file, caught by a test written for it rather than by review.
  if (!Number.isFinite(stamped)) {
    return {
      kind: 'outside-window',
      reason:
        `The timestamp on this message could not be read, so how old it is cannot be ` +
        `established. It is not shown.`,
    };
  }

  const age = opts.now.getTime() - stamped;

  if (age > opts.windowMs) {
    return {
      kind: 'outside-window',
      reason:
        `This message is stamped older than the window this client checks against, so ` +
        `whether it has been delivered before can no longer be established. It is not a ` +
        `replay as far as anything here can tell — it is simply too old to judge.`,
    };
  }

  // ⚠️ THE WINDOW IS TWO-SIDED. A one-sided "not too old" check is a common
  // miss: a message stamped far in the future never becomes too old, so it
  // stays acceptable indefinitely and its store entry is pruned out from under
  // it — a replay that works forever, built out of one timestamp.
  if (-age > opts.windowMs) {
    return {
      kind: 'outside-window',
      reason:
        `This message is stamped further ahead in the future than clock skew explains. ` +
        `It is not shown: a future timestamp never expires, which would put it beyond ` +
        `replay checking permanently.`,
    };
  }

  const duplicate = seen.some(
    (s) => s.sender === message.sender && s.sequence === message.sequence
  );

  if (duplicate) {
    return {
      kind: 'replay',
      reason:
        `A message from ${message.sender} with this sequence has already been delivered to ` +
        `this client. It is not shown again: a correctly signed message re-delivered is ` +
        `still a replay, and the signature says nothing about how many times it arrived.`,
    };
  }

  return { kind: 'fresh' };
}
