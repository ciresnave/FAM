import { test, expect, describe, beforeAll } from 'bun:test';
import { generateKeyPair, generateEncryptionKeyPair, bufferToBase64 } from '../../crypto/keys';
import { prepareSealedDirect } from '../../crypto/outgoing';
import { readIncoming } from '../receive';

// ============================================================================
// ⚠️ OPENING IS WHERE A SEALED MESSAGE STOPS BEING JSON AT A PERSON.
//
// Measured against a real server before writing this: a sealed message reaches
// the recipient with `sealed: 1` and `text` set to the ENVELOPE JSON. A client
// that does not open it prints
//
//     {"version":1,"sender":"a@…","recipient":"b@…","sealed":{…}}
//
// as the message body. That is the same failure `assertNotSealed` guards for
// the at-rest mechanism, and it arrives with no error at all.
//
// ⚠️ AND OPENING ALONE IS NOT ENOUGH. The envelope is SIGNED, and a signature
// nobody checks is decoration. Anyone who knows a recipient's published
// encryption key can seal to them — that key is public by construction — so
// decryption proves only that the message was meant for this recipient, NEVER
// who wrote it. If the sender binding is not verified, the recipient attributes
// content to a sender who did not write it, which is worse than not reading it.
//
// So `readIncoming` REQUIRES the sender's public key. There is no argument list
// that lets a caller decrypt without deciding about authenticity.
// ============================================================================

let alice: { publicKey: Uint8Array; privateKey: Uint8Array };
let mallory: { publicKey: Uint8Array; privateKey: Uint8Array };
let bobEnc: { publicKey: Uint8Array; privateKey: Uint8Array };

const ALICE = 'alice@example.com';
const BOB = 'bob@example.com';

beforeAll(async () => {
  alice = await generateKeyPair();
  mallory = await generateKeyPair();
  bobEnc = await generateEncryptionKeyPair();
});

async function sealedFrom(
  signerPrivate: Uint8Array,
  over: { senderId?: string; text?: string } = {}
) {
  const decision = await prepareSealedDirect({
    senderId: over.senderId ?? ALICE,
    senderIdentityPrivateKey: bufferToBase64(signerPrivate),
    recipientId: BOB,
    recipientEncryptionPublicKey: bufferToBase64(bobEnc.publicKey),
    text: over.text ?? 'the message body',
    sequence: 1,
  });
  if (!decision.sealed) throw new Error('fixture should seal');
  return decision.envelope;
}

function incoming(envelope: unknown, sealed = true) {
  return {
    sealed,
    text: typeof envelope === 'string' ? envelope : JSON.stringify(envelope),
    from_entity: ALICE,
  };
}

const bobPrivate = () => bufferToBase64(bobEnc.privateKey);
const alicePublic = () => bufferToBase64(alice.publicKey);

describe('an unsealed message', () => {
  test('passes through untouched', async () => {
    const result = await readIncoming(
      { sealed: false, text: 'just text', from_entity: ALICE },
      { recipientEncryptionPrivateKey: bobPrivate(), senderIdentityPublicKey: alicePublic() }
    );

    expect(result.kind).toBe('plaintext');
    if (result.kind !== 'plaintext') throw new Error('unreachable');
    expect(result.text).toBe('just text');
  });
});

describe('a sealed message from the sender it claims', () => {
  test('opens to the original text', async () => {
    const envelope = await sealedFrom(alice.privateKey, { text: 'opened correctly' });

    const result = await readIncoming(incoming(envelope), {
      recipientEncryptionPrivateKey: bobPrivate(),
      senderIdentityPublicKey: alicePublic(),
    });

    expect(result.kind).toBe('opened');
    if (result.kind !== 'opened') throw new Error('unreachable');
    expect(result.text).toBe('opened correctly');
  });
});

describe('⚠️ a sealed message whose signature does not match the claimed sender', () => {
  test('is UNREADABLE, not shown with a warning', async () => {
    // Mallory knows Bob's encryption key — it is PUBLIC by construction, that
    // is the whole point of publishing it — so Mallory can seal a message Bob
    // can decrypt, claiming to be Alice. Decryption succeeds. Only the
    // signature says otherwise.
    //
    // Showing this labelled would still put Mallory's words on Bob's screen
    // under Alice's name, and a label is a thing a person can miss. The content
    // is withheld.
    const forged = await sealedFrom(mallory.privateKey, { text: 'TRUST-ME-SENTINEL' });

    const result = await readIncoming(incoming(forged), {
      recipientEncryptionPrivateKey: bobPrivate(),
      senderIdentityPublicKey: alicePublic(),
    });

    expect(result.kind).toBe('unreadable');
    if (result.kind !== 'unreadable') throw new Error('unreachable');
    expect(result.reason).toMatch(/signature|sender/i);

    // ⚠️ The decisive assertion. A forged message's TEXT must not reach the
    // caller by any field, or a renderer that prints whatever it finds shows it.
    expect(JSON.stringify(result)).not.toContain('TRUST-ME-SENTINEL');
  });
});

describe('⚠️ a sealed message that cannot be opened', () => {
  test('never falls back to showing the envelope JSON', async () => {
    // The failure measured against the real server: `text` IS the envelope, so
    // "show text on error" prints a JSON blob at a person as though someone
    // had written it.
    const envelope = await sealedFrom(alice.privateKey);
    const wrongKey = bufferToBase64((await generateEncryptionKeyPair()).privateKey);

    const result = await readIncoming(incoming(envelope), {
      recipientEncryptionPrivateKey: wrongKey,
      senderIdentityPublicKey: alicePublic(),
    });

    expect(result.kind).toBe('unreadable');
    if (result.kind !== 'unreadable') throw new Error('unreachable');
    expect(result.reason).not.toContain('ephemeralPublicKey');
    expect(result.reason).not.toContain('ciphertext');
  });

  test('malformed JSON in a sealed row is reported, not thrown', async () => {
    // A row marked sealed whose text is not an envelope is a real state — a
    // truncated write, an older format. It must produce a reportable result
    // rather than an exception that takes down a whole history render.
    const result = await readIncoming(incoming('not json at all'), {
      recipientEncryptionPrivateKey: bobPrivate(),
      senderIdentityPublicKey: alicePublic(),
    });

    expect(result.kind).toBe('unreadable');
  });

  test('⚠️ a recipient with NO encryption key is told why, specifically', async () => {
    // An entity that predates publishing has no private half. That is a fact
    // about the entity with a remedy, not a corrupt message, and the two need
    // different words: one says "generate a key", the other says "this message
    // is damaged".
    const envelope = await sealedFrom(alice.privateKey);

    const result = await readIncoming(incoming(envelope), {
      recipientEncryptionPrivateKey: null,
      senderIdentityPublicKey: alicePublic(),
    });

    expect(result.kind).toBe('unreadable');
    if (result.kind !== 'unreadable') throw new Error('unreachable');
    expect(result.reason).toMatch(/no encryption key|publish/i);
  });
});

describe('the sender binding is checked, not just the signature', () => {
  test('an envelope naming a different sender than the row does not open', async () => {
    // The envelope signs `sender`. If the row says the message came from Alice
    // and the envelope says it came from someone else, one of the two is lying
    // and the recipient must not pick silently.
    const envelope = await sealedFrom(alice.privateKey, { senderId: 'someone-else@x.com' });

    const result = await readIncoming(
      { sealed: true, text: JSON.stringify(envelope), from_entity: ALICE },
      {
        recipientEncryptionPrivateKey: bobPrivate(),
        senderIdentityPublicKey: alicePublic(),
      }
    );

    expect(result.kind).toBe('unreadable');
  });
});
