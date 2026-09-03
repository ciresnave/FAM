import { test, expect, describe } from 'bun:test';
import { generateKeyPair, bufferToBase64 } from '../keys';
import {
  signVoucher,
  verifyVoucher,
  signRevocation,
  verifyRevocation,
  resolveEntityKey,
  canonicalVoucherBytes,
  canonicalRevocationBytes,
  type SignedVoucher,
  type SignedRevocation,
} from '../voucher';

// ============================================================================
// Vouchers: an account key binding an entity id to an entity public key.
//
// ⚠️ WHAT THIS EXISTS TO FIX, and it is the whole reason the increment is worth
// building: EVERY SIGNATURE CHECK IN FAM TODAY TERMINATES AT A VALUE THE SERVER
// CONTROLS. `entities.public_key` is a column in the server's own database,
// served to peers via /entities/list and verified against by the server itself.
// A malicious home server does not need anyone's private key — it publishes its
// own public key for an entity and forges freely. The victim's key is untouched,
// perfectly safe, and irrelevant, because nobody was checking against it.
//
// ⚠️ AND THE WRONG VERSION OF THIS FIX LOOKS FINISHED. A voucher chain rooted in
// an account key that FAM also serves passes every signature check, reads as a
// completed federation trust model, and defends against nothing the relay does
// — more signatures, same trust root. VOUCHERS WITHOUT AN ANCHOR THE RELAY
// CANNOT WRITE TO SOUND LIKE A FIX AND ARE NOT ONE.
//
// So `verifyVoucher` takes the account public key as a PARAMETER the caller
// must supply. It cannot fetch one, and FAM must never serve one: the anchor is
// the account holder's own forge repository. That is a property of the system
// rather than of these functions, which is exactly why it is written here — the
// functions are correct either way, and correctness of the functions is not the
// property that matters.
// ============================================================================

async function account() {
  const k = await generateKeyPair();
  return { publicKey: bufferToBase64(k.publicKey), privateKey: bufferToBase64(k.privateKey) };
}

const ACCOUNT = 'alice@example.com';
const ENTITY = `agent@${ACCOUNT}`;

describe('a voucher binds an entity to a key under the account key', () => {
  test('it verifies under the account key that signed it', async () => {
    const acct = await account();
    const entityKey = bufferToBase64((await generateKeyPair()).publicKey);

    const voucher = await signVoucher(acct.privateKey, {
      account: ACCOUNT,
      entity: ENTITY,
      entityPublicKey: entityKey,
      issuedAt: '2026-09-02T20:00:00.000Z',
      expiresAt: '2099-01-01T00:00:00.000Z',
      sequence: 1,
    });

    expect(await verifyVoucher(acct.publicKey, voucher)).toBe(true);
  });

  test('it does NOT verify under a different account key', async () => {
    const acct = await account();
    const impostor = await account();
    const entityKey = bufferToBase64((await generateKeyPair()).publicKey);

    const voucher = await signVoucher(acct.privateKey, {
      account: ACCOUNT,
      entity: ENTITY,
      entityPublicKey: entityKey,
      issuedAt: '2026-09-02T20:00:00.000Z',
      expiresAt: '2099-01-01T00:00:00.000Z',
      sequence: 1,
    });

    expect(await verifyVoucher(impostor.publicKey, voucher)).toBe(false);
  });

  test('SUBSTITUTING THE ENTITY KEY BREAKS IT — the attack this exists to stop', async () => {
    // The relay's move, exactly: leave everything intact and swap the public
    // key for one it holds the private half of. Under today's code that
    // succeeds silently because the relay IS the directory. Under a voucher it
    // has to forge the account signature, which it cannot.
    const acct = await account();
    const real = bufferToBase64((await generateKeyPair()).publicKey);
    const relayKey = bufferToBase64((await generateKeyPair()).publicKey);

    const voucher = await signVoucher(acct.privateKey, {
      account: ACCOUNT,
      entity: ENTITY,
      entityPublicKey: real,
      issuedAt: '2026-09-02T20:00:00.000Z',
      expiresAt: '2099-01-01T00:00:00.000Z',
      sequence: 1,
    });

    const substituted: SignedVoucher = { ...voucher, entityPublicKey: relayKey };
    expect(await verifyVoucher(acct.publicKey, substituted)).toBe(false);
    // Control: the untouched voucher still verifies, so the rejection is about
    // the substitution and not about the voucher being broken.
    expect(await verifyVoucher(acct.publicKey, voucher)).toBe(true);
  });

  test('changing the entity id breaks it', async () => {
    const acct = await account();
    const voucher = await signVoucher(acct.privateKey, {
      account: ACCOUNT,
      entity: ENTITY,
      entityPublicKey: bufferToBase64((await generateKeyPair()).publicKey),
      issuedAt: '2026-09-02T20:00:00.000Z',
      expiresAt: '2099-01-01T00:00:00.000Z',
      sequence: 1,
    });

    expect(
      await verifyVoucher(acct.publicKey, { ...voucher, entity: `other@${ACCOUNT}` })
    ).toBe(false);
  });

  test('changing the account, timestamp or sequence breaks it', async () => {
    const acct = await account();
    const base = {
      account: ACCOUNT,
      entity: ENTITY,
      entityPublicKey: bufferToBase64((await generateKeyPair()).publicKey),
      issuedAt: '2026-09-02T20:00:00.000Z',
      expiresAt: '2099-01-01T00:00:00.000Z',
      sequence: 1,
    };
    const voucher = await signVoucher(acct.privateKey, base);

    expect(await verifyVoucher(acct.publicKey, { ...voucher, account: 'mallory@x' })).toBe(false);
    expect(
      await verifyVoucher(acct.publicKey, { ...voucher, issuedAt: '2027-01-01T00:00:00.000Z' })
    ).toBe(false);
    expect(await verifyVoucher(acct.publicKey, { ...voucher, sequence: 99 })).toBe(false);
  });
});

describe('field boundaries are unambiguous', () => {
  // Same defect as the message envelope: unprefixed fields let one signature
  // cover two different readings. Here the fields that can be re-split are the
  // account and the entity, and the entity id CONTAINS the account id — so the
  // splice is not hypothetical, it is the natural shape of the data.
  test('two different splits of the same characters sign differently', () => {
    const common = {
      entityPublicKey: 'AAAA',
      issuedAt: '2026-09-02T20:00:00.000Z',
      expiresAt: '2099-01-01T00:00:00.000Z',
      sequence: 1,
      version: 1,
    };
    const a = canonicalVoucherBytes({ ...common, account: 'ab@x', entity: 'c@y' });
    const b = canonicalVoucherBytes({ ...common, account: 'ab@xc', entity: '@y' });

    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });

  test('identical fields encode identically', () => {
    const fields = {
      account: ACCOUNT,
      entity: ENTITY,
      entityPublicKey: 'AAAA',
      issuedAt: '2026-09-02T20:00:00.000Z',
      expiresAt: '2099-01-01T00:00:00.000Z',
      sequence: 1,
      version: 1,
    };
    expect(
      Buffer.from(canonicalVoucherBytes(fields)).equals(Buffer.from(canonicalVoucherBytes(fields)))
    ).toBe(true);
  });
});

describe('revocation, and which record wins', () => {
  test('a revocation verifies under the account key', async () => {
    const acct = await account();
    const revocation = await signRevocation(acct.privateKey, {
      account: ACCOUNT,
      entity: ENTITY,
      revokedAt: '2026-09-02T21:00:00.000Z',
      sequence: 2,
    });

    expect(await verifyRevocation(acct.publicKey, revocation)).toBe(true);
  });

  test('the two record types sign under DIFFERENT domains', () => {
    // ⚠️ THIS TEST EXISTS BECAUSE A MUTANT SURVIVED. Collapsing both domain
    // constants to one value left all fifteen tests passing, because the
    // cross-type test below is ALSO satisfied by the shape check
    // (`!('revokedAt' in v)`). Two independent defences, each masking the other
    // — the same disjunction as the sealing KDF, and I had written them up as
    // deliberate defence-in-depth without testing either alone.
    //
    // Domain separation is not redundant with the shape check. The two records
    // have different field COUNTS, so with length prefixing a collision needs
    // one field's content to absorb another's prefix — unlikely, but a crafted
    // `issuedAt` is exactly the kind of value an attacker chooses. The domain
    // makes the encodings disjoint by construction rather than by luck.
    //
    // Asserted at the seam because the distinguishing operation — compare the
    // two encoders on the same logical content — is one no caller performs.
    const voucherBytes = canonicalVoucherBytes({
      version: 1, account: 'a', entity: 'e', entityPublicKey: 'k',
      issuedAt: '2026-09-02T20:00:00.000Z', sequence: 1,
      expiresAt: '2099-01-01T00:00:00.000Z',
    });
    const revocationBytes = canonicalRevocationBytes({
      version: 1, account: 'a', entity: 'e',
      revokedAt: '2026-09-02T20:00:00.000Z', sequence: 1,
    });

    expect(firstField(voucherBytes)).not.toBe(firstField(revocationBytes));
    // Control: the reader works, so a difference is a real difference and not
    // two empty strings compared.
    expect(firstField(voucherBytes).length).toBeGreaterThan(0);
  });

  test('a revocation is NOT accepted as a voucher, or vice versa', async () => {
    // ⚠️ Domain separation. Without distinct signing domains, a signature over
    // one record could be presented as the other — and the two say opposite
    // things about whether an entity may be trusted.
    const acct = await account();
    const voucher = await signVoucher(acct.privateKey, {
      account: ACCOUNT,
      entity: ENTITY,
      entityPublicKey: bufferToBase64((await generateKeyPair()).publicKey),
      issuedAt: '2026-09-02T20:00:00.000Z',
      expiresAt: '2099-01-01T00:00:00.000Z',
      sequence: 1,
    });

    expect(
      await verifyRevocation(acct.publicKey, voucher as unknown as SignedRevocation)
    ).toBe(false);
  });

  test('the highest sequence wins, and a revocation ends the entity', async () => {
    const acct = await account();
    const key1 = bufferToBase64((await generateKeyPair()).publicKey);

    const voucher = await signVoucher(acct.privateKey, {
      account: ACCOUNT, entity: ENTITY, entityPublicKey: key1,
      issuedAt: '2026-09-02T20:00:00.000Z', sequence: 1,
      expiresAt: '2099-01-01T00:00:00.000Z',
    });
    const revocation = await signRevocation(acct.privateKey, {
      account: ACCOUNT, entity: ENTITY,
      revokedAt: '2026-09-02T21:00:00.000Z', sequence: 2,
    });

    const resolved = await resolveEntityKey(acct.publicKey, ENTITY, [voucher, revocation]);
    expect(resolved.status).toBe('revoked');
  });

  test('⚠️ AN OLDER VOUCHER CANNOT UNDO A REVOCATION — rollback is the relay attack', async () => {
    // A relay that cannot forge can still CHOOSE WHAT TO SHOW. Replaying a
    // superseded voucher after a revocation is the cheapest attack available to
    // it, and every record involved is perfectly valid. Resolution must be by
    // sequence, not by arrival order or by "the last one I was handed".
    const acct = await account();
    const key1 = bufferToBase64((await generateKeyPair()).publicKey);

    const voucher = await signVoucher(acct.privateKey, {
      account: ACCOUNT, entity: ENTITY, entityPublicKey: key1,
      issuedAt: '2026-09-02T20:00:00.000Z', sequence: 1,
      expiresAt: '2099-01-01T00:00:00.000Z',
    });
    const revocation = await signRevocation(acct.privateKey, {
      account: ACCOUNT, entity: ENTITY,
      revokedAt: '2026-09-02T21:00:00.000Z', sequence: 2,
    });

    // The revoked entity's records, presented in the order that favours the relay.
    const resolved = await resolveEntityKey(acct.publicKey, ENTITY, [revocation, voucher]);
    expect(resolved.status).toBe('revoked');
  });

  test('⚠️ AT EQUAL SEQUENCE A REVOCATION WINS, in either order', async () => {
    // ⚠️ FOUND BY ENUMERATING THE PATHS, prompted by a complexity finding on
    // this function. The comparison was `record.sequence <= best.sequence`, so
    // at EQUAL sequence the first record in array order won — and the relay
    // controls that order, because the relay hands the peer the record list.
    //
    // It cannot forge either record. It does not need to: if an account holder
    // ever issues a voucher and a revocation at the same sequence — a mistake,
    // but an available one — THE RELAY CHOOSES WHETHER THE ENTITY IS LIVE OR
    // REVOKED. That is the V3 attack surviving in a corner the rollback test
    // did not reach, because that test used sequences 1 and 2.
    //
    // Resolved by failing CLOSED: a revocation beats a voucher at equal
    // sequence. A revoked entity treated as live is silent and dangerous; a
    // live entity treated as revoked is loud and recoverable.
    const acct = await account();
    const key = bufferToBase64((await generateKeyPair()).publicKey);

    const voucher = await signVoucher(acct.privateKey, {
      account: ACCOUNT, entity: ENTITY, entityPublicKey: key,
      issuedAt: '2026-09-02T20:00:00.000Z', sequence: 2,
      expiresAt: '2099-01-01T00:00:00.000Z',
    });
    const revocation = await signRevocation(acct.privateKey, {
      account: ACCOUNT, entity: ENTITY,
      revokedAt: '2026-09-02T20:00:00.000Z', sequence: 2,
    });

    // BOTH orders, because order-independence is the property under test and a
    // single ordering cannot demonstrate it.
    expect((await resolveEntityKey(acct.publicKey, ENTITY, [voucher, revocation])).status).toBe(
      'revoked'
    );
    expect((await resolveEntityKey(acct.publicKey, ENTITY, [revocation, voucher])).status).toBe(
      'revoked'
    );
  });

  test('two vouchers at equal sequence resolve the same way in either order', async () => {
    // The control for the rule above. Fail-closed on a voucher/revocation tie
    // must not become "array order decides" for any other tie — if two vouchers
    // collide the answer must still not depend on who ordered the list.
    const acct = await account();
    const keyA = bufferToBase64((await generateKeyPair()).publicKey);
    const keyB = bufferToBase64((await generateKeyPair()).publicKey);

    const a = await signVoucher(acct.privateKey, {
      account: ACCOUNT, entity: ENTITY, entityPublicKey: keyA,
      issuedAt: '2026-09-02T20:00:00.000Z', sequence: 3,
      expiresAt: '2099-01-01T00:00:00.000Z',
    });
    const b = await signVoucher(acct.privateKey, {
      account: ACCOUNT, entity: ENTITY, entityPublicKey: keyB,
      issuedAt: '2026-09-02T20:00:00.000Z', sequence: 3,
      expiresAt: '2099-01-01T00:00:00.000Z',
    });

    const forward = await resolveEntityKey(acct.publicKey, ENTITY, [a, b]);
    const backward = await resolveEntityKey(acct.publicKey, ENTITY, [b, a]);
    expect(forward).toEqual(backward);
  });

  test('a later voucher rotates the key', async () => {
    const acct = await account();
    const key1 = bufferToBase64((await generateKeyPair()).publicKey);
    const key2 = bufferToBase64((await generateKeyPair()).publicKey);

    const first = await signVoucher(acct.privateKey, {
      account: ACCOUNT, entity: ENTITY, entityPublicKey: key1,
      issuedAt: '2026-09-02T20:00:00.000Z', sequence: 1,
      expiresAt: '2099-01-01T00:00:00.000Z',
    });
    const second = await signVoucher(acct.privateKey, {
      account: ACCOUNT, entity: ENTITY, entityPublicKey: key2,
      issuedAt: '2026-09-02T22:00:00.000Z', sequence: 2,
      expiresAt: '2099-01-01T00:00:00.000Z',
    });

    const resolved = await resolveEntityKey(acct.publicKey, ENTITY, [second, first]);
    expect(resolved.status).toBe('valid');
    expect(resolved.status === 'valid' && resolved.entityPublicKey).toBe(key2);
  });
});

describe('resolution refuses what it cannot verify', () => {
  test('records that do not verify are DISCARDED, not merely ranked lower', async () => {
    // ⚠️ The relay's other move: inject a high-sequence forgery. If unverified
    // records participated in ranking at all, a forgery with sequence 999 would
    // win — or, if it lost, would still have influenced the outcome. They must
    // be removed before any comparison.
    const acct = await account();
    const impostor = await account();
    const realKey = bufferToBase64((await generateKeyPair()).publicKey);
    const forgedKey = bufferToBase64((await generateKeyPair()).publicKey);

    const real = await signVoucher(acct.privateKey, {
      account: ACCOUNT, entity: ENTITY, entityPublicKey: realKey,
      issuedAt: '2026-09-02T20:00:00.000Z', sequence: 1,
      expiresAt: '2099-01-01T00:00:00.000Z',
    });
    const forged = await signVoucher(impostor.privateKey, {
      account: ACCOUNT, entity: ENTITY, entityPublicKey: forgedKey,
      issuedAt: '2026-09-02T23:00:00.000Z', sequence: 999,
      expiresAt: '2099-01-01T00:00:00.000Z',
    });

    const resolved = await resolveEntityKey(acct.publicKey, ENTITY, [real, forged]);
    expect(resolved.status).toBe('valid');
    expect(resolved.status === 'valid' && resolved.entityPublicKey).toBe(realKey);
  });

  test('a record for a DIFFERENT entity does not resolve this one', async () => {
    const acct = await account();
    const otherKey = bufferToBase64((await generateKeyPair()).publicKey);

    const other = await signVoucher(acct.privateKey, {
      account: ACCOUNT, entity: `someone-else@${ACCOUNT}`, entityPublicKey: otherKey,
      issuedAt: '2026-09-02T20:00:00.000Z', sequence: 5,
      expiresAt: '2099-01-01T00:00:00.000Z',
    });

    const resolved = await resolveEntityKey(acct.publicKey, ENTITY, [other]);
    expect(resolved.status).toBe('unknown');
  });

  test('no records at all is UNKNOWN, not valid and not revoked', async () => {
    // Three outcomes, deliberately. "I have no vouchers for this entity" is a
    // different fact from "this entity was revoked", and collapsing them either
    // trusts an unvouched key or reports a revocation that never happened.
    const acct = await account();
    const resolved = await resolveEntityKey(acct.publicKey, ENTITY, []);
    expect(resolved.status).toBe('unknown');
  });
});

/** Read the first length-prefixed field — the signing domain. */
function firstField(bytes: Uint8Array): string {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const len = view.getUint32(0, false);
  return new TextDecoder().decode(bytes.slice(4, 4 + len));
}

// ============================================================================
// Expiry — putting a clock on the one attack signatures cannot see.
//
// ⚠️ THE RELAY CAN STILL WITHHOLD, and no signature check detects an omission:
// a server that simply does not hand a peer the revocation leaves that peer
// trusting a revoked key, indefinitely and invisibly. Ordering is handled;
// ABSENCE cannot be, by any purely local check. SIGNATURE CHECKS ARE EXISTENCE
// PROOFS AND HAVE NOTHING TO SAY ABOUT ABSENCE.
//
// Expiry does not eliminate the censor. It puts a clock on them: withholding
// only works until the current voucher lapses, after which the relay must
// supply a fresh one it cannot forge. AN UNDETECTABLE INDEFINITE ATTACK
// BECOMES A BOUNDED ONE.
//
// ⚠️ REVOCATIONS DO NOT EXPIRE, and the asymmetry is deliberate. An expiring
// revocation would let a revoked entity SILENTLY COME BACK — the failure this
// whole module exists to prevent, reintroduced by the mechanism meant to
// bound it. Vouchers are claims that decay; revocations are permanent.
// ============================================================================

describe('expiry bounds what withholding can achieve', () => {
  const ISSUED = '2026-09-02T20:00:00.000Z';
  const EXPIRES = '2026-09-03T20:00:00.000Z';
  const BEFORE = new Date('2026-09-03T10:00:00.000Z');
  const AFTER = new Date('2026-09-04T10:00:00.000Z');

  test('a voucher inside its window is valid', async () => {
    const acct = await account();
    const key = bufferToBase64((await generateKeyPair()).publicKey);
    const v = await signVoucher(acct.privateKey, {
      account: ACCOUNT, entity: ENTITY, entityPublicKey: key,
      issuedAt: ISSUED, expiresAt: EXPIRES, sequence: 1,
    });

    const resolved = await resolveEntityKey(acct.publicKey, ENTITY, [v], BEFORE);
    expect(resolved.status).toBe('valid');
  });

  test('past its expiry it is EXPIRED, not valid and not unknown', async () => {
    // Three outcomes were already distinct; this makes four. "Expired" is a
    // different fact from "revoked" (the holder did not withdraw it) and from
    // "unknown" (a voucher exists and was seen). Collapsing expired into
    // unknown would hide that the peer IS being kept on stale data, which is
    // the exact signal withholding produces.
    const acct = await account();
    const key = bufferToBase64((await generateKeyPair()).publicKey);
    const v = await signVoucher(acct.privateKey, {
      account: ACCOUNT, entity: ENTITY, entityPublicKey: key,
      issuedAt: ISSUED, expiresAt: EXPIRES, sequence: 1,
    });

    const resolved = await resolveEntityKey(acct.publicKey, ENTITY, [v], AFTER);
    expect(resolved.status).toBe('expired');
  });

  test('⚠️ an expired voucher does NOT fall back to an older unexpired one', async () => {
    // The tempting bug. If resolution "helpfully" reverted to the newest
    // still-valid record, a rotation could be UNDONE by waiting: let the new
    // voucher lapse and the old key becomes current again. The holder rotated
    // for a reason, possibly because the old key was compromised.
    //
    // The winner is chosen FIRST by sequence, and only then checked for
    // validity. A lapsed winner means lapsed, not "try the runner-up".
    const acct = await account();
    const oldKey = bufferToBase64((await generateKeyPair()).publicKey);
    const newKey = bufferToBase64((await generateKeyPair()).publicKey);

    const older = await signVoucher(acct.privateKey, {
      account: ACCOUNT, entity: ENTITY, entityPublicKey: oldKey,
      issuedAt: ISSUED, expiresAt: '2099-01-01T00:00:00.000Z', sequence: 1,
    });
    const newer = await signVoucher(acct.privateKey, {
      account: ACCOUNT, entity: ENTITY, entityPublicKey: newKey,
      issuedAt: ISSUED, expiresAt: EXPIRES, sequence: 2,
    });

    const resolved = await resolveEntityKey(acct.publicKey, ENTITY, [older, newer], AFTER);
    expect(resolved.status).toBe('expired');
  });

  test('a revocation does NOT expire', async () => {
    // An expiring revocation lets a revoked entity silently come back — the
    // failure this module exists to prevent, reintroduced by the mechanism
    // meant to bound a different one.
    const acct = await account();
    const r = await signRevocation(acct.privateKey, {
      account: ACCOUNT, entity: ENTITY,
      revokedAt: ISSUED, sequence: 2,
    });

    const farFuture = new Date('2099-01-01T00:00:00.000Z');
    const resolved = await resolveEntityKey(acct.publicKey, ENTITY, [r], farFuture);
    expect(resolved.status).toBe('revoked');
  });

  test('changing expiresAt breaks the signature', async () => {
    // Otherwise the relay extends any voucher indefinitely and the clock is
    // decorative — which would be worse than no expiry, because the peer would
    // believe it had a bound.
    const acct = await account();
    const v = await signVoucher(acct.privateKey, {
      account: ACCOUNT, entity: ENTITY,
      entityPublicKey: bufferToBase64((await generateKeyPair()).publicKey),
      issuedAt: ISSUED, expiresAt: EXPIRES, sequence: 1,
    });

    expect(
      await verifyVoucher(acct.publicKey, { ...v, expiresAt: '2099-01-01T00:00:00.000Z' })
    ).toBe(false);
  });
});

describe('a malformed expiry must FAIL CLOSED', () => {
  // ⚠️ FOUND WHEN THE PM ASKED "hold if you have anything" BEFORE MERGING, which
  // made me re-derive the semantics instead of trusting a version I had written
  // hours earlier. Measured on Bun:
  //
  //     Date.parse('not a date')  ->  NaN
  //     NaN <= now                ->  FALSE
  //
  // So `if (Date.parse(expiresAt) <= now)` read an UNPARSEABLE expiry as NOT
  // EXPIRED. A voucher carrying `expiresAt: "soon"` is well-formed, verifies
  // under the account key, and never lapses. VALID FOREVER.
  //
  // ⚠️ The direction is what makes it serious rather than untidy. The whole
  // point of expiry is to fail CLOSED — and a bound whose parse failure grants
  // PERMANENCE is worse than no bound, because the peer believes it has a
  // clock. Self-inflicted rather than a relay attack, but a holder who typos an
  // expiry gets an eternal voucher and never finds out.
  //
  // TWO guards, answering different questions, each tested alone:
  //   verifyVoucher    refuses to accept it at all
  //   resolveEntityKey treats it as expired if it arrived some other way
  const ACCT_ENTITY = ENTITY;

  test('a malformed expiry never resolves as valid, by whichever guard', async () => {
    // ⚠️ NAMED FOR WHAT IT ASSERTS, after the first name overstated it. I called
    // this "resolution treats it as EXPIRED" and it does not: verification
    // rejects the record first, so resolution returns 'unknown' and never sees
    // the expiry check at all. Measured — reverting the resolution guard to the
    // fails-open form leaves every test passing, because the verification guard
    // masks it.
    //
    // The two guards are NOT independently observable, and saying so is the
    // point. This asserts the property that actually holds: a malformed expiry
    // does not yield a usable key. Which guard stops it is not something this
    // test can see, and claiming otherwise would be the sixth masked defence
    // documented as a virtue today.
    const acct = await account();
    const v = await signVoucher(acct.privateKey, {
      account: ACCOUNT, entity: ACCT_ENTITY,
      entityPublicKey: bufferToBase64((await generateKeyPair()).publicKey),
      issuedAt: '2026-09-03T04:00:00.000Z',
      expiresAt: 'soon',
      sequence: 1,
    });

    // Bypasses verifyVoucher's own guard by asking resolution directly, which
    // is the point: this arm must hold even if a record got in some other way.
    const resolved = await resolveEntityKey(acct.publicKey, ACCT_ENTITY, [v], new Date());
    expect(resolved.status).not.toBe('valid');
  });

  test('verification refuses a voucher whose expiry does not parse', async () => {
    const acct = await account();
    const v = await signVoucher(acct.privateKey, {
      account: ACCOUNT, entity: ACCT_ENTITY,
      entityPublicKey: bufferToBase64((await generateKeyPair()).publicKey),
      issuedAt: '2026-09-03T04:00:00.000Z',
      expiresAt: '',
      sequence: 1,
    });

    expect(await verifyVoucher(acct.publicKey, v)).toBe(false);

    // Control: an identical voucher with a PARSEABLE expiry does verify, so the
    // refusal is about the timestamp and not about the fixture being broken.
    const ok = await signVoucher(acct.privateKey, {
      account: ACCOUNT, entity: ACCT_ENTITY,
      entityPublicKey: bufferToBase64((await generateKeyPair()).publicKey),
      issuedAt: '2026-09-03T04:00:00.000Z',
      expiresAt: '2099-01-01T00:00:00.000Z',
      sequence: 1,
    });
    expect(await verifyVoucher(acct.publicKey, ok)).toBe(true);
  });
});
