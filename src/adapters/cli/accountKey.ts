// The account key, and the vouchers it signs.
//
// ─────────────────────────────────────────────────────────────────────────────
// ⚠️ THE VOUCHER CHAIN WAS BUILT AND HAD NEVER RUN OUTSIDE A TEST.
//
// Measured before this file existed: `fetchAccountKey`, `signVoucher`,
// `signRevocation`, `resolveEntityKey` and the key-pin `observe` each had ZERO
// call sites outside their own module and its tests, and `MessageSendService`
// consulted the chain zero times. Every primitive, route and storage layer
// present and individually correct — and the capability absent from the running
// system. The same shape as message sealing before it was wired.
// ─────────────────────────────────────────────────────────────────────────────
//
// ⚠️ WHAT THE CHAIN IS FOR, stated because it is easy to conflate with sealing:
// confidentiality from the relay is genuine BY CONSTRUCTION — FAM never holds
// an X25519 private half. Authenticity is not. **The server still serves the
// public key a recipient verifies against**, so today's guarantee is "the relay
// cannot read your mail" and NOT "the relay cannot tell you the wrong sender".
// An account key held by the human, vouching for entity keys, is what closes
// the second — and it is the only link in the chain the relay cannot rewrite.
//
// ⚠️ NOTHING HERE PUBLISHES TO A FORGE. This produces the bytes and tells the
// holder where they go. Pushing to someone's repository on their behalf is
// their action, not this tool's, and an account key appearing in a public repo
// is not something that can be walked back.

import { generateKeyPair, bufferToBase64 } from '../../crypto/keys';
import { encryptPrivateKey, decryptPrivateKey } from '../../crypto/encrypt';
import { signVoucher, type SignedVoucher } from '../../crypto/voucher';
import type { EncryptedKeyFile } from '../../types';

/**
 * Where the public half must live in the holder's forge profile repository.
 *
 * ⚠️ A CONSTANT, NOT PROSE IN A HELP STRING. `fetchAccountKey` builds its URL
 * from this exact path; a holder told to publish anywhere else produces a chain
 * that cannot resolve, and nothing errors until someone tries to verify a
 * message. Asserted against the fetcher in the tests.
 */
export const ACCOUNT_KEY_REPO_PATH = 'fam/account.pub';

/** How long a minted voucher stands before it must be reissued. */
const VOUCHER_LIFETIME_DAYS = 90;

export interface GeneratedAccountKey {
  /** Base64 raw Ed25519 public key — the half that gets published. */
  publicKey: string;
  /** Private half, encrypted under the passkey. Never leaves the holder. */
  keyFile: EncryptedKeyFile;
}

/**
 * Generate an account keypair, client-side.
 *
 * ⚠️ CLIENT-SIDE IS THE WHOLE POINT. An account key minted by the server would
 * leave the relay able to vouch for any entity in the account, which is exactly
 * the authority this key exists to move off the server. It is the same
 * reasoning that moved entity identity keys client-side, one tier up.
 */
export async function generateAccountKey(
  passkey: string,
  accountId: string
): Promise<GeneratedAccountKey> {
  const pair = await generateKeyPair();
  const publicKey = bufferToBase64(pair.publicKey);

  // The key file binds to the ACCOUNT id. `EncryptedKeyFile.entity_id` is the
  // identifier field; here it holds an account. Reusing the container is
  // deliberate — one audited encryption path rather than a second one — and
  // the field's contents are named honestly wherever this file is read.
  const keyFile = await encryptPrivateKey(
    bufferToBase64(pair.privateKey),
    passkey,
    accountId,
    publicKey
  );

  return { publicKey, keyFile };
}

/** The private half, decrypted. Throws on a wrong passkey. */
export async function readAccountPrivateKey(
  keyFile: EncryptedKeyFile,
  passkey: string
): Promise<string> {
  return decryptPrivateKey(keyFile, passkey);
}

/**
 * Exactly the bytes that belong in the published file.
 *
 * ⚠️ BARE BASE64, NO WRAPPER AND NO HEADER, because that is what
 * `fetchAccountKey` accepts: it trims, then requires a raw 32-byte key and
 * rejects anything else. A JSON envelope or a PEM banner here would produce a
 * file that publishes cleanly and fails at every fetch — a producer and its
 * consumer disagreeing, which is the failure this project keeps finding.
 * Asserted by round-tripping through the real fetcher in the tests.
 */
export function publishableAccountKey(publicKey: string): string {
  return publicKey;
}

export interface MintVoucherInput {
  accountId: string;
  /** Base64 Ed25519 private key. Never transmitted. */
  accountPrivateKey: string;
  entityId: string;
  /** The entity's IDENTITY public key, the thing being vouched for. */
  entityPublicKey: string;
  /** Monotonic per entity. Resolution is by sequence, never arrival order. */
  sequence: number;
  /** Overridable so tests can pin it. */
  now?: Date;
}

/**
 * Sign a voucher binding an entity to its identity key.
 *
 * The expiry is REQUIRED by the record type and is set here rather than left to
 * a caller: a signature check is an existence proof and has nothing to say
 * about an omission, so a relay that withholds a revocation leaves a peer
 * trusting a revoked key. Expiry does not remove that censor — it bounds them.
 */
export async function mintVoucher(input: MintVoucherInput): Promise<SignedVoucher> {
  const now = input.now ?? new Date();
  const expires = new Date(now.getTime() + VOUCHER_LIFETIME_DAYS * 24 * 60 * 60 * 1000);

  return signVoucher(input.accountPrivateKey, {
    account: input.accountId,
    entity: input.entityId,
    entityPublicKey: input.entityPublicKey,
    issuedAt: now.toISOString(),
    expiresAt: expires.toISOString(),
    sequence: input.sequence,
  });
}
