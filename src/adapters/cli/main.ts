#!/usr/bin/env bun
/**
 * FAM CLI - Human Interface for Federated Agent Messaging
 *
 * Usage:
 *   bun src/adapters/cli/main.ts auth [--provider google|github]
 *   bun src/adapters/cli/main.ts entity create <name> [--type agent|human|tool] [--passkey <passkey>]
 *   bun src/adapters/cli/main.ts entity list
 *   bun src/adapters/cli/main.ts send <to_entity|channel:name> <message>
 *   bun src/adapters/cli/main.ts history [--channel <channel_id>] [--entity <entity_id>] [--limit <n>]
 *   bun src/adapters/cli/main.ts channels list
 *   bun src/adapters/cli/main.ts channels create <name> [--public]
 *   bun src/adapters/cli/main.ts channels join <channel_id>
 *   bun src/adapters/cli/main.ts channels members <channel_id>
 *   bun src/adapters/cli/main.ts channels invite <channel_id> <entity_id>
 *   bun src/adapters/cli/main.ts channels invitations
 */

import { runAuthCommand } from './commands/auth';
import { runEntityCommand } from './commands/entity';
import { runSendCommand } from './commands/message';
import { runHistoryCommand } from './commands/message';
import { runChannelCommand } from './commands/channel';
import { runAccountCommand } from './commands/account';
import { loadCredentials, type CliConfig } from './config';
import { DEFAULT_SERVER_URL } from '../../config';

// ============================================================================
// Logging
// ============================================================================

function log(msg: string) {
  console.error(`[fam-cli] ${msg}`);
}

function fatal(msg: string): never {
  console.error(`[fam-cli] FATAL: ${msg}`);
  process.exit(1);
}

// ============================================================================
// Help
// ============================================================================

function printHelp() {
  console.log(`
FAM CLI - Federated Agent Messaging

USAGE:
  fam <command> [subcommand] [options]

COMMANDS:
  auth                    Authenticate with FAM server via OAuth
    --provider <name>     OAuth provider (google, github). Default: google

  entity                  Manage entities
    create <name>         Create a new entity
      --type <type>       Entity type (agent, human, tool). Default: human
      --passkey <key>     Passkey for encrypting private key
    list                  List your entities
    switch [entity_id]    Switch active entity (lists if no ID given)
    availability <available|unavailable>
                          Pause or resume incoming messages

  send <target> <message> Send a message. SEALED by default: the server
                          cannot read it.
    target:               Entity ID (user@email.com) or channel:name
    --plaintext           Send unsealed if an intended reader has published
                          no encryption key. Without this, such a send is
                          REFUSED rather than quietly downgraded, and the
                          error names who is missing one.
                          A channel seals to every member, all-or-nothing.

  account                 Manage this account's signing key
    init-key              Generate the account key that signs vouchers.
                          Prints the public half and where to publish it;
                          it does NOT push to your forge.
    vouch <entity_id>     Sign and publish a voucher binding an entity to
                          its identity key, so a peer can verify who sent
                          a message without trusting the relay.

  history                 Get message history
    --channel <id>        Channel ID
    --entity <id>         Other entity ID (for DMs)
    --limit <n>           Max messages (default: 50)

  channels                Manage channels
    list                  List channels
    create <name>         Create a channel
      --public            Make channel public (default: false)
    join <channel_id>     Join a channel
    members <channel_id>  List channel members
    invite <id> <entity>  Invite entity to private channel
    invitations           List pending invitations

OPTIONS:
  --server <url>          FAM server URL (default: ${DEFAULT_SERVER_URL})
  --entity <id>           Entity ID to use (default: from credentials)
  --help                  Show this help
  --version               Show version

ENVIRONMENT:
  FAM_SERVER_URL          FAM server URL
  FAM_SERVER_SECRET       Server secret (for token hashing)
  FAM_PASSKEY             Passkey for decrypting private key
`);
}

// ============================================================================
// Argument Parser
// ============================================================================

interface ParsedArgs {
  command: string;
  subcommand: string | null;
  positional: string[];
  flags: Record<string, string | boolean>;
}

function parseArgs(args: string[]): ParsedArgs {
  const positional: string[] = [];
  const flags: Record<string, string | boolean> = {};
  
  let i = 0;
  while (i < args.length) {
    const arg = args[i]!;
    
    if (arg === '--help' || arg === '-h') {
      flags.help = true;
    } else if (arg === '--version' || arg === '-v') {
      flags.version = true;
    } else if (arg.startsWith('--')) {
      const key = arg.slice(2);
      const next = args[i + 1];
      if (next && !next.startsWith('--')) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = true;
      }
    } else {
      positional.push(arg);
    }
    
    i++;
  }
  
  return {
    command: positional[0] || 'help',
    subcommand: positional[1] || null,
    positional: positional.slice(2),
    flags,
  };
}

// ============================================================================
// Main
// ============================================================================

async function main() {
  const args = parseArgs(process.argv.slice(2));
  
  if (args.flags.help || args.command === 'help') {
    printHelp();
    return;
  }
  
  if (args.flags.version) {
    console.log('fam-cli 0.1.0');
    return;
  }
  
  // Load config
  const config: CliConfig = {
    serverUrl: (args.flags.server as string) || process.env.FAM_SERVER_URL || DEFAULT_SERVER_URL,
    entityId: (args.flags.entity as string) || null,
    passkey: process.env.FAM_PASSKEY || null,
  };
  
  try {
    switch (args.command) {
      case 'auth':
        await runAuthCommand(args.subcommand, args.flags, config);
        break;
        
      case 'entity':
        await runEntityCommand(args.subcommand, args.positional, args.flags, config);
        break;
        
      case 'send':
        if (args.positional.length < 2) {
          fatal('Usage: fam send <target> <message>');
        }
        await runSendCommand(args.positional[0]!, args.positional.slice(1).join(' '), config, args.flags);
        break;
        
      case 'history':
        await runHistoryCommand(args.flags, config);
        break;
        
      case 'channels':
        await runChannelCommand(args.subcommand, args.positional, args.flags, config);
        break;

      case 'account':
        await runAccountCommand(args.subcommand, args.positional, args.flags, config);
        break;
        
      default:
        console.error(`Unknown command: ${args.command}`);
        printHelp();
        process.exit(1);
    }
  } catch (e) {
    if (e instanceof Error) {
      fatal(e.message);
    } else {
      fatal(String(e));
    }
  }
}

main();
