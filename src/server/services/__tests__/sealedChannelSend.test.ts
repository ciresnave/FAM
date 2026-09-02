import { test, expect, describe, beforeEach, afterEach } from 'bun:test';
import { Database } from 'bun:sqlite';
import { createContext } from '../../../db/transaction';
import { initializeDatabase } from '../../../db/schema';
import { AccountRepository } from '../../../db/repositories/account';
import { MessageSendService } from '../messageSend';
import { PermissionChecker } from '../permissionChecker';
import { generateKeyPair, generateEncryptionKeyPair, bufferToBase64 } from '../../../crypto/keys';
import { sealToMany, openGroup } from '../../../crypto/groupSealing';
import { signGroupEnvelope, type SignedGroupEnvelope } from '../../../crypto/envelope';
import type { WebSocketManager } from '../../websocket';
import { ValidationError, EntityNotInChannelError } from '../../../types/errors';

// ============================================================================
// Sealed channel messages.
//
// ⚠️ THE RECIPIENT SET INCLUDES THE SENDER, AND THAT IS NOT THE SAME SET AS THE
// DELIVERY SET. `insertChannelMessage` deliberately excludes the sender from
// delivery rows — you do not get pushed your own message. But if the sender is
// not a RECIPIENT of the seal, the sender can never decrypt their own message
// from history: the server holds a row they cannot read, and their own outbox
// is unreadable to them.
//
// So: who can DECRYPT is every member including the sender; who gets PUSHED is
// every member except the sender. Two different sets that were one set before
// sealing existed, and collapsing them is the obvious mistake.
//
// ⚠️ AND THE SET MUST MATCH EXACTLY. A subset means some members silently hold
// a message they cannot open — the failure looks like "nothing arrived" and is
// diagnosed nowhere near the send. A superset means the sender chose who could
// read a channel message, which is the channel's decision, not theirs.
// ============================================================================

class RecordingWsManager {
  pushes: Array<{ entityId: string; message: any }> = [];
  pushToEntity(entityId: string, message: any): void {
    this.pushes.push({ entityId, message });
  }
}

describe('sealed channel messages', () => {
  const ACCOUNT = 'sealedchan.example.com';
  const ALICE = `alice@${ACCOUNT}`;
  const BOB = `bob@${ACCOUNT}`;
  const CAROL = `carol@${ACCOUNT}`;
  const KEYLESS = `keyless@${ACCOUNT}`;

  let db: Database;
  let ctx: ReturnType<typeof createContext>;
  let service: MessageSendService;
  let wsManager: RecordingWsManager;
  let channelId: string;

  const identity: Record<string, { publicKey: Uint8Array; privateKey: Uint8Array }> = {};
  const encryption: Record<string, { publicKey: Uint8Array; privateKey: Uint8Array }> = {};

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

    new AccountRepository(db).create(ACCOUNT, 'Test');

    for (const id of [ALICE, BOB, CAROL, KEYLESS]) {
      identity[id] = await generateKeyPair();
      encryption[id] = await generateEncryptionKeyPair();
      ctx.entities.create(id, ACCOUNT, 'agent', bufferToBase64(identity[id]!.publicKey));
    }
    // KEYLESS deliberately publishes no encryption key.
    for (const id of [ALICE, BOB, CAROL]) {
      ctx.entities.setEncryptionKey(id, bufferToBase64(encryption[id]!.publicKey));
    }

    const channel = ctx.channels.create('sealed-room', ALICE, false);
    channelId = channel.id;
    ctx.channels.addMember(channelId, ALICE, 'owner');
    ctx.channels.addMember(channelId, BOB, 'member');
    ctx.channels.addMember(channelId, CAROL, 'member');
  });

  afterEach(() => db.close());

  /** Build a correctly-addressed sealed channel envelope from ALICE. */
  async function envelopeFor(
    text: string,
    members: string[] = [ALICE, BOB, CAROL]
  ): Promise<SignedGroupEnvelope> {
    const sealed = await sealToMany(
      members.map((id) => ({
        entity: id,
        publicKey: bufferToBase64(encryption[id]!.publicKey),
      })),
      text
    );
    return signGroupEnvelope(bufferToBase64(identity[ALICE]!.privateKey), {
      sender: ALICE,
      channel: channelId,
      sentAt: new Date().toISOString(),
      sequence: 1,
      sealed,
    });
  }

  test('every member including the sender can decrypt what was stored', async () => {
    const envelope = await envelopeFor('standup at ten');
    const { message } = await service.sendSealedChannelMessage(ALICE, channelId, envelope);

    const row = db
      .prepare('SELECT sealed, text FROM messages WHERE id = ?')
      .get(message.id) as { sealed: number; text: string };
    expect(row.sealed).toBe(1);
    expect(row.text).not.toContain('standup at ten');

    const stored = JSON.parse((await ctx.messages.getById(message.id))!.text) as SignedGroupEnvelope;
    for (const id of [ALICE, BOB, CAROL]) {
      expect(await openGroup(id, bufferToBase64(encryption[id]!.privateKey), stored.sealed)).toBe(
        'standup at ten'
      );
    }
  });

  test('the sender is a RECIPIENT but is not PUSHED', async () => {
    // The two sets differ, and both halves are asserted. Excluding the sender
    // from the seal would leave them unable to read their own outbox; pushing
    // to them would echo their own message back.
    const envelope = await envelopeFor('mine to read');
    await service.sendSealedChannelMessage(ALICE, channelId, envelope);

    const pushedTo = wsManager.pushes.map((p) => p.entityId);
    expect(pushedTo).not.toContain(ALICE);
    expect(pushedTo.sort()).toEqual([BOB, CAROL].sort());

    const deliveries = db
      .prepare('SELECT recipient_entity_id FROM message_deliveries')
      .all() as Array<{ recipient_entity_id: string }>;
    expect(deliveries.map((d) => d.recipient_entity_id)).not.toContain(ALICE);
  });

  test('a recipient set MISSING a member is refused', async () => {
    // Carol would hold a message she cannot open. That failure surfaces as
    // "nothing arrived" and is diagnosed nowhere near the send.
    const envelope = await envelopeFor('not for carol', [ALICE, BOB]);

    await expect(
      service.sendSealedChannelMessage(ALICE, channelId, envelope)
    ).rejects.toThrow(/carol/i);
  });

  test('a recipient set with an EXTRA entity is refused', async () => {
    // Who may read a channel message is the channel's decision, not the
    // sender's. An extra recipient is the sender granting read access.
    const outsider = `outsider@${ACCOUNT}`;
    identity[outsider] = await generateKeyPair();
    encryption[outsider] = await generateEncryptionKeyPair();
    ctx.entities.create(outsider, ACCOUNT, 'agent', bufferToBase64(identity[outsider]!.publicKey));
    ctx.entities.setEncryptionKey(outsider, bufferToBase64(encryption[outsider]!.publicKey));

    const envelope = await envelopeFor('plus one', [ALICE, BOB, CAROL, outsider]);

    await expect(
      service.sendSealedChannelMessage(ALICE, channelId, envelope)
    ).rejects.toThrow(/outsider/i);
  });

  test('a correctly addressed envelope is accepted', async () => {
    // The control for both refusals. Without it each is satisfied by a method
    // that rejects everything.
    const { message } = await service.sendSealedChannelMessage(ALICE, channelId, await envelopeFor('ok'));
    expect(message.id).toBeGreaterThan(0);
  });

  test('a keyless member blocks the send, diagnosed as keyless and not as misaddressed', async () => {
    // ⚠️ MASKED ON OUTCOME, measured: deleting the keyless check entirely still
    // rejects and still names the same entity, because a keyless member is also
    // a member absent from the envelope, so the `missing` check fires instead.
    // Asserting `/keyless/i` alone passed with the guard gone.
    //
    // The two messages point at DIFFERENT PEOPLE, which is why the guard earns
    // its place:
    //
    //   keyless -> the member must publish a key. The sender cannot fix it.
    //   missing -> the sender addressed the envelope wrong. Retrying the same
    //              way fails forever, and it looks like their bug.
    //
    // Refused as a whole rather than sealed to everyone else, either way:
    // sealing to the members who CAN receive is the silent-partial-delivery
    // shape — the sender believes the channel got it, and one member never sees
    // it, with no error anywhere.
    ctx.channels.addMember(channelId, KEYLESS, 'member');

    await expect(
      service.sendSealedChannelMessage(ALICE, channelId, await envelopeFor('blocked'))
    ).rejects.toThrow(/published no encryption key/i);

    await expect(
      service.sendSealedChannelMessage(ALICE, channelId, await envelopeFor('blocked'))
    ).rejects.not.toThrow(/missing recipients/i);
  });

  test('a non-member cannot send', async () => {
    const stranger = `stranger@${ACCOUNT}`;
    identity[stranger] = await generateKeyPair();
    ctx.entities.create(stranger, ACCOUNT, 'agent', bufferToBase64(identity[stranger]!.publicKey));

    await expect(
      service.sendSealedChannelMessage(stranger, channelId, await envelopeFor('intruder'))
    ).rejects.toThrow(EntityNotInChannelError);
  });

  test('an envelope naming a different channel is refused', async () => {
    const other = ctx.channels.create('elsewhere', ALICE, false);
    const envelope = await envelopeFor('misrouted');
    const misaddressed = { ...envelope, channel: other.id };

    await expect(
      service.sendSealedChannelMessage(ALICE, channelId, misaddressed)
    ).rejects.toThrow(/channel/i);
  });

  test('an envelope whose signature does not verify is refused', async () => {
    const sealed = await sealToMany(
      [ALICE, BOB, CAROL].map((id) => ({
        entity: id,
        publicKey: bufferToBase64(encryption[id]!.publicKey),
      })),
      'forged'
    );
    // Signed by Bob, claiming to be from Alice.
    const envelope = await signGroupEnvelope(bufferToBase64(identity[BOB]!.privateKey), {
      sender: ALICE,
      channel: channelId,
      sentAt: new Date().toISOString(),
      sequence: 1,
      sealed,
    });

    await expect(
      service.sendSealedChannelMessage(ALICE, channelId, envelope)
    ).rejects.toThrow(/signature/i);
  });

  test('a malformed envelope is refused rather than stored opaque', async () => {
    await expect(
      service.sendSealedChannelMessage(ALICE, channelId, { nonsense: true } as any)
    ).rejects.toThrow(ValidationError);
  });

  test('DEMONSTRATION: membership lost in the check-to-persist window stops the write', async () => {
    // Kills the inner race guard, which no static test can see — the outer
    // membership check refuses first for every non-racing case.
    const envelope = await envelopeFor('raced');
    const before = (db.prepare('SELECT COUNT(*) as n FROM messages').get() as { n: number }).n;

    const sending = service.sendSealedChannelMessage(ALICE, channelId, envelope).catch(() => null);
    // Same synchronous block, so it lands before the awaited crypto resumes.
    ctx.channels.removeMember(channelId, ALICE);
    await sending;

    expect((db.prepare('SELECT COUNT(*) as n FROM messages').get() as { n: number }).n).toBe(before);
  });
});
