// The authenticity half of a message.
//
// `sealing.ts` gives confidentiality and says NOTHING about who sent anything —
// anyone holding a public key can seal to it. This module signs the sealed
// envelope with the sender's Ed25519 identity key, which is what makes a
// message attributable WITHOUT TRUSTING THE RELAY THAT CARRIED IT. Today a
// message's authenticity is a claim by whichever server delivered it; under
// this, forging one requires a private key.
//
// The two halves stay separate on purpose, and the separation is load-bearing
// in the direction people get wrong: DECRYPTION SUCCEEDING IS NOT
// AUTHENTICATION. A recipient's public key is public, so anyone can produce
// ciphertext that recipient opens cleanly. Only the signature says who did.

import { sign, verify, base64ToBuffer } from './keys';
import { open, type SealedEnvelope } from './sealing';
import type { SealedGroupEnvelope } from './groupSealing';
import type { EntityId } from '../types';
import { SignatureInvalidError } from '../types/errors';

const ENVELOPE_VERSION = 1;
const DOMAIN = 'fam-envelope-v1';

export interface EnvelopeFields {
  /** Sender entity id, `name@account`. */
  sender: string;
  /** Recipient entity id, `name@account`. */
  recipient: string;
  /** ISO-8601 instant the sender stamped. */
  sentAt: string;
  /** Per-sender counter. Replay protection lives on this. */
  sequence: number;
  /** The sealed body. Signed over, never inspected here. */
  sealed: SealedEnvelope;
}

export interface SignedEnvelope extends EnvelopeFields {
  version: number;
  /** Ed25519 signature over `canonicalBytes`, base64. */
  signature: string;
}

/**
 * The exact bytes a signature covers.
 *
 * ⚠️ EVERY FIELD IS LENGTH-PREFIXED, AND THAT IS THE WHOLE POINT. Join fields
 * without their lengths and
 *
 *     sender "ab@x"  recipient "c@y"
 *     sender "ab@xc" recipient "@y"
 *
 * produce identical bytes, so ONE signature is valid for BOTH. A relay moves
 * the split and the message is attributed to a different sender, or addressed
 * to a different recipient, with the signature still checking out.
 *
 * No round-trip test can see this: both envelopes verify correctly against
 * their own contents. The defect is that they are not their own.
 *
 * Exported because the property is worth asserting directly rather than only
 * through a signature that happens to differ.
 */
export function canonicalBytes(fields: EnvelopeFields & { version: number }): Uint8Array {
  const parts = [
    DOMAIN,
    String(fields.version),
    fields.sender,
    fields.recipient,
    fields.sentAt,
    String(fields.sequence),
    String(fields.sealed.version),
    fields.sealed.ephemeralPublicKey,
    fields.sealed.iv,
    fields.sealed.ciphertext,
  ];

  return lengthPrefixed(parts);
}

/**
 * Concatenate strings, each preceded by its byte length as a big-endian uint32.
 *
 * Shared by the flat and group envelopes deliberately. Two copies of a
 * serialisation are two things that can drift, and a drift here means a
 * signature that verifies against bytes the other side did not produce.
 */
function lengthPrefixed(parts: string[]): Uint8Array {
  const encoder = new TextEncoder();
  const encoded = parts.map((p) => encoder.encode(p));
  const total = encoded.reduce((n, p) => n + 4 + p.length, 0);

  const out = new Uint8Array(new ArrayBuffer(total));
  const view = new DataView(out.buffer);
  let offset = 0;
  for (const part of encoded) {
    view.setUint32(offset, part.length, false); // big-endian length prefix
    offset += 4;
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** Sign a set of envelope fields with the sender's Ed25519 private key. */
export async function signEnvelope(
  senderPrivateKeyBase64: string,
  fields: EnvelopeFields
): Promise<SignedEnvelope> {
  const version = ENVELOPE_VERSION;
  const signature = await sign(canonicalBytes({ version, ...fields }), senderPrivateKeyBase64);
  return { version, ...fields, signature };
}

/**
 * Check an envelope against the sender's Ed25519 public key.
 *
 * Returns a boolean to match `keys.verify`. Prefer `openSigned` at call sites
 * that then read the message — a boolean is easy to not look at, and an
 * unchecked signature is the same as no signature.
 */
export async function verifyEnvelope(
  senderPublicKeyBase64: string,
  envelope: SignedEnvelope
): Promise<boolean> {
  try {
    return await verify(
      canonicalBytes(envelope),
      envelope.signature,
      senderPublicKeyBase64
    );
  } catch {
    // A malformed signature is a failed verification, not a crash. Ed25519
    // rejects a wrong-length input by throwing, and a caller cannot act
    // differently on the two cases anyway.
    return false;
  }
}

/**
 * Verify, then open.
 *
 * ORDER MATTERS AND IS NOT AN OPTIMISATION: the signature is checked before the
 * ciphertext is touched, so an unauthenticated envelope never reaches the
 * decryption path at all.
 */
export async function openSigned(
  senderPublicKeyBase64: string,
  recipientPrivateKeyBase64: string,
  envelope: SignedEnvelope
): Promise<string> {
  if (!(await verifyEnvelope(senderPublicKeyBase64, envelope))) {
    throw new SignatureInvalidError();
  }
  return open(recipientPrivateKeyBase64, envelope.sealed);
}

// ============================================================================
// Group envelopes — the channel case
// ============================================================================

const GROUP_DOMAIN = 'fam-group-envelope-v1';

export interface GroupEnvelopeFields {
  sender: EntityId;
  /** Channel id. A group envelope is addressed to a channel, never to an entity. */
  channel: string;
  sentAt: string;
  sequence: number;
  sealed: SealedGroupEnvelope;
}

export interface SignedGroupEnvelope extends GroupEnvelopeFields {
  version: number;
  signature: string;
}

/**
 * The exact bytes a group signature covers.
 *
 * ⚠️ THE RECIPIENT LIST IS COUNT-PREFIXED AND EVERY FIELD LENGTH-PREFIXED, for
 * the same reason the flat envelope's fields are, but with an extra failure the
 * flat case does not have: a list.
 *
 * Without the count, appending a recipient to a shorter list and removing one
 * from a longer list can produce identical bytes — so one signature would cover
 * two different recipient sets, and the set is exactly what decides WHO CAN
 * READ. Without per-field prefixes the same splice attack applies inside a
 * recipient as it does between sender and recipient in the flat case.
 *
 * Signing the whole list rather than a digest of it is deliberate: a digest
 * would be one more construction to get right, and the list is small.
 */
export function canonicalGroupBytes(
  fields: GroupEnvelopeFields & { version: number }
): Uint8Array {
  const parts = [
    GROUP_DOMAIN,
    String(fields.version),
    fields.sender,
    fields.channel,
    fields.sentAt,
    String(fields.sequence),
    String(fields.sealed.version),
    fields.sealed.iv,
    fields.sealed.ciphertext,
    // The COUNT, so a list of n cannot be confused with a list of n±1.
    String(fields.sealed.recipients.length),
  ];

  for (const r of fields.sealed.recipients) {
    parts.push(r.entity, r.ephemeralPublicKey, r.iv, r.wrappedKey);
  }

  return lengthPrefixed(parts);
}

/** Sign a group envelope with the sender's Ed25519 private key. */
export async function signGroupEnvelope(
  senderPrivateKeyBase64: string,
  fields: GroupEnvelopeFields
): Promise<SignedGroupEnvelope> {
  const version = ENVELOPE_VERSION;
  const signature = await sign(
    canonicalGroupBytes({ version, ...fields }),
    senderPrivateKeyBase64
  );
  return { version, ...fields, signature };
}

/** Check a group envelope against the sender's Ed25519 public key. */
export async function verifyGroupEnvelope(
  senderPublicKeyBase64: string,
  envelope: SignedGroupEnvelope
): Promise<boolean> {
  try {
    return await verify(
      canonicalGroupBytes(envelope),
      envelope.signature,
      senderPublicKeyBase64
    );
  } catch {
    return false;
  }
}

/** Reserved: `base64ToBuffer` is re-exported for callers assembling envelopes. */
export { base64ToBuffer };
