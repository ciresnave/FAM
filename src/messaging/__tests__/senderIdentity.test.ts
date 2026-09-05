import { test, expect, describe, beforeAll } from 'bun:test';
import { generateKeyPair, bufferToBase64 } from '../../crypto/keys';
import { signVoucher, signRevocation } from '../../crypto/voucher';
import { resolveSenderIdentity } from '../senderIdentity';

// ============================================================================
// ⚠️ WHOSE KEY IS THE RECIPIENT VERIFYING AGAINST?
//
// Until now: the server's. FAM never holds an X25519 private half, so
// confidentiality from the relay is genuine by construction — but the relay
// still SERVES the identity key a recipient checks signatures with. So the
// guarantee was "the relay cannot read your mail", never "the relay cannot tell
// you the wrong sender".
//
// The voucher chain replaces that key with one signed by the account holder.
// This module decides, for one sender, which key to use — or that none may be
// used at all.
//
// ⚠️ THE STATE THAT MATTERS MOST IS DISAGREEMENT. A chain that resolves to key
// A while the server serves key B is not an error condition — IT IS THE ATTACK
// THIS WHOLE TIER EXISTS TO DETECT, and it must refuse rather than pick.
// Picking the vouched one silently would be defensible and would also throw
// away the only evidence that anything happened.
//
// ⚠️ AND "NO VOUCHER" IS NOT A DOWNGRADE. Every entity is in that state today.
// It is the STATUS QUO — the server's word, exactly as before — and it is
// labelled rather than silently accepted. Refusing it would break every
// existing deployment to enforce a guarantee nobody has yet published a key
// for; there is no verified state being fallen back FROM.
// ============================================================================

const ACCOUNT = 'holder@example.com';
const ENTITY = `agent@${ACCOUNT}`;

let accountKeys: { publicKey: Uint8Array; privateKey: Uint8Array };
let entityKeys: { publicKey: Uint8Array; privateKey: Uint8Array };
let otherKeys: { publicKey: Uint8Array; privateKey: Uint8Array };

beforeAll(async () => {
  accountKeys = await generateKeyPair();
  entityKeys = await generateKeyPair();
  otherKeys = await generateKeyPair();
});

const accountPublic = () => bufferToBase64(accountKeys.publicKey);
const entityPublic = () => bufferToBase64(entityKeys.publicKey);
const otherPublic = () => bufferToBase64(otherKeys.publicKey);

async function voucherFor(publicKey: string, sequence = 1, lifetimeMs = 86_400_000) {
  const now = new Date();
  return signVoucher(bufferToBase64(accountKeys.privateKey), {
    account: ACCOUNT,
    entity: ENTITY,
    entityPublicKey: publicKey,
    issuedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + lifetimeMs).toISOString(),
    sequence,
  });
}

describe('a chain that resolves and agrees with the server', () => {
  test('is vouched, and the vouched key is the one returned', async () => {
    const resolution = await resolveSenderIdentity({
      entityId: ENTITY,
      serverSuppliedKey: entityPublic(),
      accountPublicKey: accountPublic(),
      records: [await voucherFor(entityPublic())],
    });

    expect(resolution.kind).toBe('vouched');
    if (resolution.kind !== 'vouched') throw new Error('unreachable');
    expect(resolution.publicKey).toBe(entityPublic());
  });
});

describe('⚠️ a chain that resolves and DISAGREES with the server', () => {
  test('REFUSES — this is the attack, not a preference', async () => {
    // The relay serves one key; the account holder vouched for another. Picking
    // the vouched one silently would be defensible and would discard the only
    // evidence that a substitution was attempted.
    const resolution = await resolveSenderIdentity({
      entityId: ENTITY,
      serverSuppliedKey: otherPublic(),
      accountPublicKey: accountPublic(),
      records: [await voucherFor(entityPublic())],
    });

    expect(resolution.kind).toBe('refused');
    if (resolution.kind !== 'refused') throw new Error('unreachable');
    expect(resolution.reason).toMatch(/differ|disagree|does not match/i);
  });

  test('and the refusal carries NO key, so a caller cannot use one anyway', async () => {
    const resolution = await resolveSenderIdentity({
      entityId: ENTITY,
      serverSuppliedKey: otherPublic(),
      accountPublicKey: accountPublic(),
      records: [await voucherFor(entityPublic())],
    });

    expect('publicKey' in resolution).toBe(false);
  });
});

describe('a revoked or expired chain', () => {
  test('revoked REFUSES', async () => {
    const voucher = await voucherFor(entityPublic(), 1);
    const revocation = await signRevocation(bufferToBase64(accountKeys.privateKey), {
      account: ACCOUNT,
      entity: ENTITY,
      revokedAt: new Date().toISOString(),
      sequence: 2,
    });

    const resolution = await resolveSenderIdentity({
      entityId: ENTITY,
      serverSuppliedKey: entityPublic(),
      accountPublicKey: accountPublic(),
      records: [voucher, revocation],
    });

    expect(resolution.kind).toBe('refused');
    if (resolution.kind !== 'refused') throw new Error('unreachable');
    expect(resolution.reason).toMatch(/revoked/i);
  });

  test('⚠️ expired REFUSES, and says so distinctly from revoked', async () => {
    // Expiry is what bounds a relay that withholds a revocation: a signature
    // check is an existence proof and has nothing to say about an omission.
    // Reporting it as "revoked" would claim the holder withdrew the key, which
    // they did not; reporting it as "unknown" would hide that the recipient is
    // being kept on stale data.
    const voucher = await voucherFor(entityPublic(), 1, -1000); // already lapsed

    const resolution = await resolveSenderIdentity({
      entityId: ENTITY,
      serverSuppliedKey: entityPublic(),
      accountPublicKey: accountPublic(),
      records: [voucher],
    });

    expect(resolution.kind).toBe('refused');
    if (resolution.kind !== 'refused') throw new Error('unreachable');
    expect(resolution.reason).toMatch(/expired|lapsed/i);
    expect(resolution.reason).not.toMatch(/revoked/i);
  });
});

describe('no chain at all — the state every entity is in today', () => {
  test('⚠️ is UNVOUCHED, not refused: it is the status quo, labelled', async () => {
    // There is no verified state being fallen back FROM. Refusing here would
    // break every existing deployment to enforce a guarantee for which nobody
    // has published a key yet.
    const resolution = await resolveSenderIdentity({
      entityId: ENTITY,
      serverSuppliedKey: entityPublic(),
      accountPublicKey: null,
      records: [],
    });

    expect(resolution.kind).toBe('unvouched');
    if (resolution.kind !== 'unvouched') throw new Error('unreachable');
    expect(resolution.publicKey).toBe(entityPublic());
  });

  test('⚠️ records WITHOUT an account key are unvouched, not a crash and not vouched', async () => {
    // ADDED BECAUSE A MUTANT SURVIVED, and the mutant turned out to be INERT:
    // removing the early `!accountPublicKey` return still produces `unvouched`,
    // because `resolveEntityKey` with a null key discards every record as
    // unverifiable and returns `unknown` rather than throwing (measured).
    //
    // So the guard is currently an equivalence, not a behaviour — and this test
    // PINS that. If `resolveEntityKey` ever started throwing on a null key, the
    // early return would become load-bearing and this is what would notice.
    // The state is realistic: a relay can serve records for an entity whose
    // account key cannot be fetched.
    const resolution = await resolveSenderIdentity({
      entityId: ENTITY,
      serverSuppliedKey: entityPublic(),
      accountPublicKey: null,
      records: [await voucherFor(entityPublic())],
    });

    expect(resolution.kind).toBe('unvouched');
    if (resolution.kind !== 'unvouched') throw new Error('unreachable');
    expect(resolution.publicKey).toBe(entityPublic());
  });

  test('an account key with no records is also unvouched', async () => {
    const resolution = await resolveSenderIdentity({
      entityId: ENTITY,
      serverSuppliedKey: entityPublic(),
      accountPublicKey: accountPublic(),
      records: [],
    });

    expect(resolution.kind).toBe('unvouched');
  });

  test('⚠️ records signed by the WRONG account key are unvouched, not vouched', async () => {
    // A relay can inject plausible records. They fail verification and are
    // discarded before ranking, so the outcome is "no chain" — never a chain
    // built from records the account holder did not sign.
    const forged = await signVoucher(bufferToBase64(otherKeys.privateKey), {
      account: ACCOUNT,
      entity: ENTITY,
      entityPublicKey: otherPublic(),
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
      sequence: 999,
    });

    const resolution = await resolveSenderIdentity({
      entityId: ENTITY,
      serverSuppliedKey: entityPublic(),
      accountPublicKey: accountPublic(),
      records: [forged],
    });

    expect(resolution.kind).toBe('unvouched');
    if (resolution.kind !== 'unvouched') throw new Error('unreachable');
    // And emphatically not the forged key.
    expect(resolution.publicKey).toBe(entityPublic());
  });
});

describe('nothing to verify against at all', () => {
  test('refuses rather than returning an empty key', async () => {
    // The unknown-sender case, one layer down: no chain AND no server key means
    // there is nothing to check a signature with, and an empty string would
    // sail into the verifier and fail as though the message were forged.
    const resolution = await resolveSenderIdentity({
      entityId: ENTITY,
      serverSuppliedKey: null,
      accountPublicKey: null,
      records: [],
    });

    expect(resolution.kind).toBe('refused');
    if (resolution.kind !== 'refused') throw new Error('unreachable');
    expect(resolution.reason).toMatch(/no key|not known|cannot/i);
  });
});
