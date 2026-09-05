// The CLI's transport for a direct send. The policy is not here.
//
// ⚠️ THIS FILE USED TO HOLD THE POLICY TOO, AND THAT WAS FINE UNTIL A SECOND
// ADAPTER NEEDED IT. The refusal rule, the "not visible is not keyless" rule
// and the post-nothing-before-refusing rule now live in
// `src/messaging/directSend.ts`, because the MCP adapter has to obey exactly
// the same ones. Copying them here and there is how one adapter ends up
// sending plaintext where the other refuses — a difference that shows up as a
// message the relay can read, never as a failure.
//
// What remains is genuinely the CLI's: it posts with `apiRequest` and an
// explicit session id, where the MCP adapter goes through `FamClient`.

import { apiRequest } from './client';
import type { CliConfig } from './config';
import {
  sendDirectVia,
  type DirectSendTransport,
  type DirectoryEntity,
  type SendOutcome,
} from '../../messaging/directSend';
import { sendChannelVia, type ChannelSendTransport } from '../../messaging/channelSend';
import type { SignedGroupEnvelope } from '../../crypto/envelope';
import type { SignedEnvelope } from '../../crypto/envelope';

export type { SendOutcome };

export interface DirectSendInput {
  senderId: string;
  senderIdentityPrivateKey: string;
  sessionId: string;
  recipientId: string;
  text: string;
  allowPlaintext?: boolean;
}

export async function sendDirect(
  config: CliConfig,
  input: DirectSendInput
): Promise<SendOutcome> {
  const transport = cliTransport(config, input.senderId, input.sessionId);

  return sendDirectVia(transport, {
    senderId: input.senderId,
    senderIdentityPrivateKey: input.senderIdentityPrivateKey,
    recipientId: input.recipientId,
    text: input.text,
    allowPlaintext: input.allowPlaintext,
  });
}

function cliTransport(
  config: CliConfig,
  entityId: string,
  sessionId: string
): DirectSendTransport {
  return {
    async listVisibleEntities(): Promise<DirectoryEntity[]> {
      const res = await apiRequest<{ entities: DirectoryEntity[] }>(config, '/entities/list', {
        entity_id: entityId,
        session_id: sessionId,
      });
      return res.entities;
    },

    async sendSealed(recipientId: string, envelope: SignedEnvelope) {
      const res = await apiRequest<{ message_id: number }>(config, '/messages/send-sealed', {
        entity_id: entityId,
        session_id: sessionId,
        to_entity: recipientId,
        envelope,
      });
      return { messageId: res.message_id, response: res };
    },

    async sendPlaintext(recipientId: string, text: string) {
      const res = await apiRequest<{ message_id: number }>(config, '/messages/send', {
        entity_id: entityId,
        session_id: sessionId,
        to_entity: recipientId,
        text,
      });
      return { messageId: res.message_id, response: res };
    },
  };
}

export interface ChannelSendInput {
  senderId: string;
  senderIdentityPrivateKey: string;
  sessionId: string;
  channelId: string;
  text: string;
  allowPlaintext?: boolean;
}

/**
 * Send to a channel, sealing to every member unless that is impossible and the
 * caller explicitly allowed otherwise.
 *
 * The policy is `sendChannelVia`'s, for the same reason the direct one is
 * shared: the MCP adapter sends to channels too, and "may this be sealed?"
 * answered in two places is two answers.
 */
export async function sendToChannel(
  config: CliConfig,
  input: ChannelSendInput
): Promise<SendOutcome> {
  const transport = cliChannelTransport(config, input.senderId, input.sessionId);

  return sendChannelVia(transport, {
    senderId: input.senderId,
    senderIdentityPrivateKey: input.senderIdentityPrivateKey,
    channelId: input.channelId,
    text: input.text,
    allowPlaintext: input.allowPlaintext,
  });
}

function cliChannelTransport(
  config: CliConfig,
  entityId: string,
  sessionId: string
): ChannelSendTransport {
  return {
    async listChannelMembers(channelId: string): Promise<DirectoryEntity[]> {
      // `scope: 'channel'` returns the members as full entities, which is where
      // `encryption_public_key` comes from. No second route was needed, and
      // adding one would have been a second answer to "may A see B".
      const res = await apiRequest<{ entities: DirectoryEntity[] }>(config, '/entities/list', {
        entity_id: entityId,
        session_id: sessionId,
        scope: 'channel',
        channel_id: channelId,
      });
      return res.entities;
    },

    async sendSealedChannel(channelId: string, envelope: SignedGroupEnvelope) {
      const res = await apiRequest<{ message_id: number }>(config, '/messages/send-sealed', {
        entity_id: entityId,
        session_id: sessionId,
        channel_id: channelId,
        envelope,
      });
      return { messageId: res.message_id, response: res };
    },

    async sendPlaintextChannel(channelId: string, text: string) {
      const res = await apiRequest<{ message_id: number }>(config, '/messages/send', {
        entity_id: entityId,
        session_id: sessionId,
        channel_id: channelId,
        text,
      });
      return { messageId: res.message_id, response: res };
    },
  };
}
