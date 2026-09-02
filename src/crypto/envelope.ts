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

/** Reserved: `base64ToBuffer` is re-exported for callers assembling envelopes. */
export { base64ToBuffer };
