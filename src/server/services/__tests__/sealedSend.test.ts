import { test, expect, describe, beforeEach, afterEach } from 'bun:test';
import { Database } from 'bun:sqlite';
import { createContext } from '../../../db/transaction';
import { initializeDatabase } from '../../../db/schema';
import { AccountRepository } from '../../../db/repositories/account';
import { MessageSendService } from '../messageSend';
import { PermissionChecker } from '../permissionChecker';
import { generateKeyPair, generateEncryptionKeyPair, bufferToBase64 } from '../../../crypto/keys';
import { seal } from '../../../crypto/sealing';
import { signEnvelope, type SignedEnvelope } from '../../../crypto/envelope';
import type { WebSocketManager } from '../../websocket';
import { ForbiddenError, ValidationError } from '../../../types/errors';

// ============================================================================
// Accepting a message the server cannot read.
//
// ⚠️ THE SERVER DOES NOT SEAL. THE SENDER DOES. If the server sealed here it
// would hold the plaintext at the moment it encrypts, which is exactly what
// `message-encryption.ts` already does and exactly the property sealing exists
// to remove. A server-sealing implementation would pass every test that could
// be written about envelopes and signatures — sealed, verifying, decryptable —
// while providing NONE of the guarantee. So the send path takes an opaque
// envelope and stores it.
//
// ⚠️ AND THE SEALED AND UNSEALED PATHS ARE SEPARATE METHODS ON PURPOSE. One
// method with an optional envelope is a disjunction — "sealed if supplied, else
// plaintext" — and a client bug that dropped the envelope would silently send
// plaintext while every test still passed. Separate methods make the caller
// NAME the path, and `messages.sealed` records which one accepted the row, so
// the fact survives instead of being inferred later.
// ============================================================================

class RecordingWsManager {
  pushes: Array<{ entityId: string; message: any }> = [];
  pushToEntity(entityId: string, message: any): void {
    this.pushes.push({ entityId, message });
  }
}

describe('sealed direct messages', () => {
  const ACCOUNT = 'sealed.example.com';
  const SENDER = `sender@${ACCOUNT}`;
  const RECEIVER = `receiver@${ACCOUNT}`;
  const OTHER = `other@${ACCOUNT}`;

  let db: Database;
  let ctx: ReturnType<typeof createContext>;
  let service: MessageSendService;
  let wsManager: RecordingWsManager;

  let senderIdentity: { publicKey: Uint8Array; privateKey: Uint8Array };
  let receiverEncryption: { publicKey: Uint8Array; privateKey: Uint8Array };

  beforeEach(async () => {
    db = new Database(':memory:');
    initializeDatabase(db);
    ctx = createContext(db);
    wsManager = new RecordingWsManager();
    service = new MessageSendService(
      ctx,
      wsManager as unknown as WebSocketManager,
      new PermissionChecker(ctx)
    );

    senderIdentity = await generateKeyPair();
    receiverEncryption = await generateEncryptionKeyPair();

    new AccountRepository(db).create(ACCOUNT, 'Test');
    ctx.entities.create(SENDER, ACCOUNT, 'agent', bufferToBase64(senderIdentity.publicKey));
    ctx.entities.create(RECEIVER, ACCOUNT, 'agent', 'pk-receiver');
    ctx.entities.create(OTHER, ACCOUNT, 'agent', 'pk-other');
  });

  afterEach(() => {
    db.close();
  });

  /** Build a properly sealed and signed envelope from SENDER to RECEIVER. */
  async function envelopeFor(
    text: string,
    over: Partial<{ sender: string; recipient: string; signWith: Uint8Array }> = {}
  ): Promise<SignedEnvelope> {
    const sealed = await seal(bufferToBase64(receiverEncryption.publicKey), text);
    return signEnvelope(bufferToBase64(over.signWith ?? senderIdentity.privateKey), {
      sender: over.sender ?? SENDER,
      recipient: over.recipient ?? RECEIVER,
      sentAt: new Date().toISOString(),
      sequence: 1,
      sealed,
    });
  }

  test('a sealed message is stored, marked sealed, and pushed opaque', async () => {
    const envelope = await envelopeFor('the server cannot read this');
    const { message } = await service.sendSealedDirectMessage(SENDER, RECEIVER, envelope);

    const row = db
      .prepare('SELECT sealed FROM messages WHERE id = ?')
      .get(message.id) as { sealed: number };
    expect(row.sealed).toBe(1);

    // The plaintext appears nowhere — not in the row, not in the push.
    const stored = db.prepare('SELECT text FROM messages WHERE id = ?').get(message.id) as {
      text: string;
    };
    expect(stored.text).not.toContain('the server cannot read this');
    expect(JSON.stringify(wsManager.pushes)).not.toContain('the server cannot read this');

    // The recipient is told it is sealed, so a client cannot mistake an
    // envelope for a message body.
    expect(wsManager.pushes.length).toBe(1);
    expect(wsManager.pushes[0]!.entityId).toBe(RECEIVER);
    expect(wsManager.pushes[0]!.message.sealed).toBe(true);
  });

  test('an ordinary message is marked NOT sealed', async () => {
    // The control. Without it, `sealed` could be 1 for everything and the test
    // above would still pass.
    const { message } = await service.sendDirectMessage(SENDER, RECEIVER, 'plain text');

    const row = db
      .prepare('SELECT sealed FROM messages WHERE id = ?')
      .get(message.id) as { sealed: number };
    expect(row.sealed).toBe(0);
    expect(wsManager.pushes[0]!.message.sealed).toBeFalsy();
  });

  test('the recipient can open what was stored', async () => {
    // End to end through the storage layer: what comes back out is still
    // openable by the recipient's key. A storage path that mangled the envelope
    // would pass every structural assertion above.
    const { open } = await import('../../../crypto/sealing');
    const envelope = await envelopeFor('the numbers are in');

    const { message } = await service.sendSealedDirectMessage(SENDER, RECEIVER, envelope);
    const readBack = await ctx.messages.getById(message.id);
    const parsed = JSON.parse(readBack!.text) as SignedEnvelope;

    expect(await open(bufferToBase64(receiverEncryption.privateKey), parsed.sealed)).toBe(
      'the numbers are in'
    );
  });
});

describe('the envelope must agree with how the message is actually routed', () => {
  // ⚠️ THE DEFECT THIS PREVENTS. The recipient verifies a signature over the
  // ENVELOPE's own sender and recipient fields. If those may differ from the
  // addressing FAM actually routed by, then a message delivered to B can carry
  // a validly-signed claim that it was addressed to C — and B's client, doing
  // everything right, reports it as a message for someone else. Or a sender
  // ships an envelope naming a different sender and the recipient attributes
  // it accordingly.
  //
  // Neither is caught by verifying the signature: the signature is VALID. It
  // is a binding failure between two layers, not a forgery.
  const ACCOUNT = 'bind.example.com';
  const SENDER = `sender@${ACCOUNT}`;
  const RECEIVER = `receiver@${ACCOUNT}`;
  const OTHER = `other@${ACCOUNT}`;

  let db: Database;
  let ctx: ReturnType<typeof createContext>;
  let service: MessageSendService;
  let senderIdentity: { publicKey: Uint8Array; privateKey: Uint8Array };
  let otherIdentity: { publicKey: Uint8Array; privateKey: Uint8Array };
  let receiverEncryption: { publicKey: Uint8Array; privateKey: Uint8Array };

  beforeEach(async () => {
    db = new Database(':memory:');
    initializeDatabase(db);
    ctx = createContext(db);
    service = new MessageSendService(
      ctx,
      new RecordingWsManager() as unknown as WebSocketManager,
      new PermissionChecker(ctx)
    );

    senderIdentity = await generateKeyPair();
    otherIdentity = await generateKeyPair();
    receiverEncryption = await generateEncryptionKeyPair();

    new AccountRepository(db).create(ACCOUNT, 'Test');
    ctx.entities.create(SENDER, ACCOUNT, 'agent', bufferToBase64(senderIdentity.publicKey));
    ctx.entities.create(RECEIVER, ACCOUNT, 'agent', 'pk-receiver');
    ctx.entities.create(OTHER, ACCOUNT, 'agent', bufferToBase64(otherIdentity.publicKey));
  });

  afterEach(() => db.close());

  async function build(fields: {
    sender: string;
    recipient: string;
    signWith: Uint8Array;
  }): Promise<SignedEnvelope> {
    const sealed = await seal(bufferToBase64(receiverEncryption.publicKey), 'body');
    return signEnvelope(bufferToBase64(fields.signWith), {
      sender: fields.sender,
      recipient: fields.recipient,
      sentAt: new Date().toISOString(),
      sequence: 1,
      sealed,
    });
  }

  test('an envelope naming a different sender is refused', async () => {
    const envelope = await build({
      sender: OTHER,
      recipient: RECEIVER,
      signWith: otherIdentity.privateKey, // validly signed BY that sender
    });

    await expect(service.sendSealedDirectMessage(SENDER, RECEIVER, envelope)).rejects.toThrow(
      /sender/i
    );
  });

  test('an envelope naming a different recipient is refused', async () => {
    const envelope = await build({
      sender: SENDER,
      recipient: OTHER,
      signWith: senderIdentity.privateKey,
    });

    await expect(service.sendSealedDirectMessage(SENDER, RECEIVER, envelope)).rejects.toThrow(
      /recipient/i
    );
  });

  test('an envelope whose signature does not verify is refused', async () => {
    const envelope = await build({
      sender: SENDER,
      recipient: RECEIVER,
      signWith: otherIdentity.privateKey, // wrong key for this sender
    });

    await expect(service.sendSealedDirectMessage(SENDER, RECEIVER, envelope)).rejects.toThrow(
      /signature/i
    );
  });

  test('a correctly bound envelope is accepted', async () => {
    // The control for all three. Without it each refusal test is satisfied by a
    // method that rejects everything.
    const envelope = await build({
      sender: SENDER,
      recipient: RECEIVER,
      signWith: senderIdentity.privateKey,
    });

    const { message } = await service.sendSealedDirectMessage(SENDER, RECEIVER, envelope);
    expect(message.id).toBeGreaterThan(0);
  });

  test('a malformed envelope is refused rather than stored opaque', async () => {
    // "The server cannot read it" is not "the server accepts anything". An
    // unparseable envelope fails at every recipient forever, so it is rejected
    // at the door rather than persisted as undeliverable mail.
    await expect(
      service.sendSealedDirectMessage(SENDER, RECEIVER, { nonsense: true } as any)
    ).rejects.toThrow(ValidationError);
  });

  // ==========================================================================
  // ⚠️ THE TWO PERMISSION CHECKS MASK EACH OTHER, AND THE STATIC-DENY TEST
  // BELOW CANNOT TELL THEM APART.
  //
  // `sendSealedDirectMessage` checks permission twice: once up front, once
  // inside the transaction. Measured — each is individually unprotected:
  //
  //     outer check removed  -> 9/9 pass   (the inner one still refuses)
  //     inner check removed  -> 9/9 pass   (the outer one still refuses)
  //
  // Same shape as the sealing KDF mutants: a verdict reached by "outer OR
  // inner", where removing either leaves the other discriminating. A campaign
  // that mutates one at a time reports both covered.
  //
  // They are not redundant. They answer different questions, and each needs the
  // test that can only see IT:
  //
  //   inner  the RACE. A revocation landing between the check and the write
  //          would otherwise still produce a stored message — the grant said no
  //          by the time the row existed. Outcome-visible only under a forced
  //          interleaving.
  //   outer  the EARLY EXIT. Same outcome, different work: without it a denied
  //          sender still makes the server run signature verification and
  //          at-rest encryption before being refused.
  // ==========================================================================

  function countMessages(): number {
    return (db.prepare('SELECT COUNT(*) as n FROM messages').get() as { n: number }).n;
  }

  function denyNow(): void {
    ctx.permissions.create({
      account_id: ACCOUNT,
      target_type: 'entity',
      target_entity_id: RECEIVER,
      source_type: 'entity',
      source_entity_id: SENDER,
      action: 'deny',
    });
  }

  test('DEMONSTRATION: a deny landing in the check-to-persist window stops the write', async () => {
    // Kills the INNER check. The ordering is FORCED: denyNow() runs in the same
    // synchronous block right after the promise is created, so it is guaranteed
    // to land before the awaited signature verification and at-rest encryption
    // resume. That proves the window exists and is wide enough to matter — not
    // how often the ordering occurs in production, where the revocation is a
    // separate request that must win a real race.
    const envelope = await build({
      sender: SENDER,
      recipient: RECEIVER,
      signWith: senderIdentity.privateKey,
    });
    const before = countMessages();

    const sending = service.sendSealedDirectMessage(SENDER, RECEIVER, envelope).catch(() => null);
    denyNow();
    await sending;

    // The invariant, not the sequence: whatever the interleaving, no message
    // exists that only a live permission would have allowed.
    expect(countMessages()).toBe(before);
  });

  test('a denied sender causes no crypto or storage work', async () => {
    // Kills the OUTER check, which has no outcome the inner one lacks — both
    // refuse, both store nothing. What only the outer one gives is that the
    // refusal happens BEFORE the work, so that is what this observes.
    //
    // White-box on purpose. The alternative was to delete the outer check as
    // unobservable, which would hand a denied sender the ability to make the
    // server verify signatures and encrypt on demand.
    denyNow();
    const envelope = await build({
      sender: SENDER,
      recipient: RECEIVER,
      signWith: senderIdentity.privateKey,
    });

    let prepareCalls = 0;
    const realPrepare = ctx.messages.prepareStoredText.bind(ctx.messages);
    ctx.messages.prepareStoredText = async (text: string) => {
      prepareCalls++;
      return realPrepare(text);
    };

    await expect(service.sendSealedDirectMessage(SENDER, RECEIVER, envelope)).rejects.toThrow(
      ForbiddenError
    );
    expect(prepareCalls).toBe(0);

    ctx.messages.prepareStoredText = realPrepare;
  });

  test('sealing does not bypass the permission matrix', async () => {
    // ⚠️ A second send path is a second place for enforcement to be missing.
    // The whole reason MessageSendService exists is that HTTP and WebSocket
    // must not answer this differently; a sealed path that skipped the check
    // would be the same defect one layer down.
    ctx.permissions.create({
      account_id: ACCOUNT,
      target_type: 'entity',
      target_entity_id: RECEIVER,
      source_type: 'entity',
      source_entity_id: SENDER,
      action: 'deny',
    });

    const envelope = await build({
      sender: SENDER,
      recipient: RECEIVER,
      signWith: senderIdentity.privateKey,
    });

    await expect(service.sendSealedDirectMessage(SENDER, RECEIVER, envelope)).rejects.toThrow(
      ForbiddenError
    );
  });
});
