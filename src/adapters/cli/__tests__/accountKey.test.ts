import { test, expect, describe } from 'bun:test';
import {
  generateAccountKey,
  readAccountPrivateKey,
  publishableAccountKey,
  ACCOUNT_KEY_REPO_PATH,
  mintVoucher,
} from '../accountKey';
import { fetchAccountKey } from '../../../federation/accountKey';
import { verifyVoucher, resolveEntityKey } from '../../../crypto/voucher';
import { generateKeyPair, bufferToBase64 } from '../../../crypto/keys';

// ============================================================================
// ⚠️ THE VOUCHER CHAIN IS BUILT AND HAS NEVER RUN OUTSIDE A TEST.
//
// Measured at `origin/main`: `fetchAccountKey`, `signVoucher`,
// `signRevocation`, `resolveEntityKey` and `observe` each have ZERO call sites
// outside their own module and its tests, and `MessageSendService` consults the
// chain zero times. Control: `prepareSealedDirect` returns one, so the query
// discriminates.
//
// So entity identity still rests on the relay's word. Confidentiality from the
// relay is genuine by construction — FAM never holds an X25519 private half —
// but THE SERVER STILL SERVES THE PUBLIC KEY A RECIPIENT VERIFIES AGAINST.
// This is the same shape as message sealing before it was wired: every
// primitive present and correct, and the capability absent from the system.
//
// ⚠️ THE DECISIVE TEST HERE IS THE ROUND TRIP THROUGH THE REAL CONSUMER.
// What this generates must be exactly what `fetchAccountKey` accepts — bare
// base64, no wrapper, no header. Testing the writer alone is how a format
// change broke every key-file reader once already: "the format was tested; the
// readers were not."
// ============================================================================

const ACCOUNT = 'holder@example.com';
const ENTITY = `agent@${ACCOUNT}`;
const PASSKEY = 'account-passkey';

describe('generating an account key', () => {
  test('⚠️ what it publishes is exactly what fetchAccountKey accepts', async () => {
    const generated = await generateAccountKey(PASSKEY, ACCOUNT);
    const fileContent = publishableAccountKey(generated.publicKey);

    // The real consumer, with the network replaced and nothing else.
    const fetched = await fetchAccountKey(
      { forge: 'github', username: 'holder' },
      async (url) => ({ ok: true, status: 200, text: async () => fileContent })
    );

    expect(fetched.publicKey).toBe(generated.publicKey);
  });

  test('a trailing newline is tolerated, because editors add one', async () => {
    const generated = await generateAccountKey(PASSKEY, ACCOUNT);

    const fetched = await fetchAccountKey(
      { forge: 'github', username: 'holder' },
      async () => ({
        ok: true,
        status: 200,
        text: async () => publishableAccountKey(generated.publicKey) + '\n',
      })
    );

    expect(fetched.publicKey).toBe(generated.publicKey);
  });

  test('⚠️ the private half is NOWHERE in the publishable content', async () => {
    // The one mistake that cannot be walked back. Publishing to a forge is
    // public and permanent, and a key file that leaked its private half would
    // hand anyone the ability to vouch for any entity in the account.
    const generated = await generateAccountKey(PASSKEY, ACCOUNT);
    const priv = await readAccountPrivateKey(generated.keyFile, PASSKEY);

    const content = publishableAccountKey(generated.publicKey);
    expect(content).not.toContain(priv);
    expect(content.trim()).toBe(generated.publicKey);
  });

  test('the private half is recoverable with the passkey and not without it', async () => {
    const generated = await generateAccountKey(PASSKEY, ACCOUNT);

    expect(await readAccountPrivateKey(generated.keyFile, PASSKEY)).toBeTruthy();
    await expect(readAccountPrivateKey(generated.keyFile, 'wrong')).rejects.toThrow();
  });

  test('the repo path matches the one the fetcher reads', async () => {
    // A constant rather than prose in a help string: the fetch URL is built
    // from `fam/account.pub`, and a holder told to publish anywhere else
    // produces a chain that cannot resolve, with no error until someone tries.
    expect(ACCOUNT_KEY_REPO_PATH).toBe('fam/account.pub');
  });
});

describe('minting a voucher', () => {
  test('the voucher verifies under the account public key', async () => {
    const account = await generateAccountKey(PASSKEY, ACCOUNT);
    const entity = await generateKeyPair();

    const voucher = await mintVoucher({
      accountId: ACCOUNT,
      accountPrivateKey: await readAccountPrivateKey(account.keyFile, PASSKEY),
      entityId: ENTITY,
      entityPublicKey: bufferToBase64(entity.publicKey),
      sequence: 1,
    });

    expect(await verifyVoucher(account.publicKey, voucher)).toBe(true);
  });

  test('⚠️ and the chain RESOLVES to the entity key, which is the whole point', async () => {
    // Verification alone says the record is genuine. Resolution is what a
    // recipient actually does: given a bag of records, which key is current?
    const account = await generateAccountKey(PASSKEY, ACCOUNT);
    const entity = await generateKeyPair();
    const entityPublicKey = bufferToBase64(entity.publicKey);

    const voucher = await mintVoucher({
      accountId: ACCOUNT,
      accountPrivateKey: await readAccountPrivateKey(account.keyFile, PASSKEY),
      entityId: ENTITY,
      entityPublicKey,
      sequence: 1,
    });

    const resolved = await resolveEntityKey(account.publicKey, ENTITY, [voucher]);

    expect(resolved.status).toBe('valid');
    if (resolved.status !== 'valid') throw new Error('unreachable');
    expect(resolved.entityPublicKey).toBe(entityPublicKey);
  });

  test('⚠️ a voucher for one entity does not resolve another', async () => {
    // The binding. An entity id contains its account id, so `account` and
    // `entity` are adjacent strings sharing a boundary — which is exactly the
    // splice the length-prefixed canonical form exists to prevent.
    const account = await generateAccountKey(PASSKEY, ACCOUNT);
    const entity = await generateKeyPair();

    const voucher = await mintVoucher({
      accountId: ACCOUNT,
      accountPrivateKey: await readAccountPrivateKey(account.keyFile, PASSKEY),
      entityId: ENTITY,
      entityPublicKey: bufferToBase64(entity.publicKey),
      sequence: 1,
    });

    const other = await resolveEntityKey(account.publicKey, `other@${ACCOUNT}`, [voucher]);
    expect(other.status).toBe('unknown');
  });

  test('⚠️ a voucher does not verify under a DIFFERENT account key', async () => {
    // The property the whole chain rests on: only the account holder can vouch.
    const account = await generateAccountKey(PASSKEY, ACCOUNT);
    const impostor = await generateAccountKey(PASSKEY, 'impostor@example.com');
    const entity = await generateKeyPair();

    const voucher = await mintVoucher({
      accountId: ACCOUNT,
      accountPrivateKey: await readAccountPrivateKey(account.keyFile, PASSKEY),
      entityId: ENTITY,
      entityPublicKey: bufferToBase64(entity.publicKey),
      sequence: 1,
    });

    expect(await verifyVoucher(impostor.publicKey, voucher)).toBe(false);
    expect((await resolveEntityKey(impostor.publicKey, ENTITY, [voucher])).status).toBe(
      'unknown'
    );
  });

  test('it carries a real expiry, and expiry is not optional', async () => {
    // `expiresAt` is what bounds a withholding relay: a signature check is an
    // existence proof and has nothing to say about an omission. A voucher with
    // no expiry is one the relay can serve forever.
    const account = await generateAccountKey(PASSKEY, ACCOUNT);
    const entity = await generateKeyPair();

    const voucher = await mintVoucher({
      accountId: ACCOUNT,
      accountPrivateKey: await readAccountPrivateKey(account.keyFile, PASSKEY),
      entityId: ENTITY,
      entityPublicKey: bufferToBase64(entity.publicKey),
      sequence: 1,
    });

    expect(Date.parse(voucher.expiresAt)).toBeGreaterThan(Date.parse(voucher.issuedAt));

    // And a resolution AFTER that instant reports expired — distinct from both
    // revoked and unknown, because being kept on stale data is its own signal.
    const after = new Date(Date.parse(voucher.expiresAt) + 1000);
    expect((await resolveEntityKey(account.publicKey, ENTITY, [voucher], after)).status).toBe(
      'expired'
    );
  });
});
