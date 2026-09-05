// Account-key commands — the tier of the key model held by the human.
//
// ⚠️ THE ACCOUNT KEY IS THE ONE LINK THE RELAY CANNOT REWRITE, and until now
// nothing could create one. Confidentiality from the relay is genuine by
// construction; authenticity is not, because the server still serves the public
// key a recipient verifies against. These two commands are what let a holder
// take that authority back.

import { apiRequest } from '../client';
import { fetchAccountKey, type Forge } from '../../../federation/accountKey';
import {
  observePeerAnchor,
  acceptPeerAnchorChange,
  getPeerAnchorKey,
} from '../peerAnchors';
import {
  generateAccountKey,
  readAccountPrivateKey,
  publishableAccountKey,
  mintVoucher,
  ACCOUNT_KEY_REPO_PATH,
} from '../accountKey';
import {
  loadAccountKeyFile,
  saveAccountKeyFile,
  getActiveEntityCredentials,
  type CliConfig,
} from '../config';
import type { EncryptedKeyFile } from '../../../types';

export async function runAccountCommand(
  subcommand: string | null,
  positional: string[],
  flags: Record<string, string | boolean>,
  config: CliConfig
): Promise<void> {
  switch (subcommand) {
    case 'init-key':
      await initKey(flags, config);
      break;
    case 'vouch':
      await vouch(positional, flags, config);
      break;
    case 'trust':
      await trust(positional, flags);
      break;
    default:
      console.log('Usage: fam account <init-key|vouch|trust>');
      console.log('');
      console.log('  init-key            Generate this account\'s signing key.');
      console.log('                      Prints the public half and where to publish it.');
      console.log('  vouch <entity_id>   Sign and publish a voucher binding an entity');
      console.log('                      to its identity key.');
      console.log('  trust <account_id> --github <user>');
      console.log('                      Fetch and pin a peer account key, so their');
      console.log('                      messages can be verified without the relay.');
      break;
  }
}

async function initKey(
  flags: Record<string, string | boolean>,
  config: CliConfig
): Promise<void> {
  const accountId = (flags.account as string) || (await inferAccountId());
  const passkey = (flags.passkey as string) || config.passkey || (await promptPasskey());

  // ⚠️ REFUSES TO OVERWRITE. A second account key silently replacing the first
  // invalidates every voucher already published under it — every entity in the
  // account becomes unresolvable at once, and the only symptom is that peers
  // stop being able to verify anyone.
  const existing = await loadAccountKeyFile();
  if (existing) {
    console.log(`An account key already exists for ${existing.entity_id}.`);
    console.log('Refusing to replace it: every voucher signed with the old key would');
    console.log('stop resolving, for every entity in this account at once.');
    console.log('Rotating an account key is a deliberate operation and is not this command.');
    return;
  }

  const generated = await generateAccountKey(passkey, accountId);
  await saveAccountKeyFile(generated.keyFile);

  console.log(`Account key generated for ${accountId} and saved locally.`);
  console.log('');
  console.log('⚠️  PUBLISH THE PUBLIC HALF YOURSELF. This tool does not push to your');
  console.log('    forge — an account key in a public repository cannot be un-published,');
  console.log('    and that is your action to take, not this tool\'s.');
  console.log('');
  console.log(`    Repository:  <your-username>/<your-username>  (your profile repo)`);
  console.log(`    Path:        ${ACCOUNT_KEY_REPO_PATH}`);
  console.log(`    Contents:    the single line below, nothing else`);
  console.log('');
  console.log(publishableAccountKey(generated.publicKey));
  console.log('');
  console.log('Until it is published, peers cannot fetch it and no voucher you sign');
  console.log('can be verified by anyone else.');
}

async function vouch(
  positional: string[],
  flags: Record<string, string | boolean>,
  config: CliConfig
): Promise<void> {
  const entityId = positional[0];
  if (!entityId) {
    throw new Error('Usage: fam account vouch <entity_id>');
  }

  const keyFile = await loadAccountKeyFile();
  if (!keyFile) {
    throw new Error(
      'No account key found. Run `fam account init-key` first — a voucher is signed ' +
        'by the account key, and without one there is nothing to sign with.'
    );
  }

  const passkey = (flags.passkey as string) || config.passkey || (await promptPasskey());
  const accountPrivateKey = await readAccountPrivateKey(keyFile, passkey);

  // ⚠️ THE ENTITY KEY COMES FROM THE LOCAL KEY FILE, NOT FROM THE SERVER.
  // Vouching for a key the server handed back would sign whatever it chose to
  // serve — the exact substitution this chain exists to detect. The holder's
  // own copy is the only source that cannot be the attacker.
  const credentials = await getActiveEntityCredentials();
  if (credentials.entity_id !== entityId) {
    throw new Error(
      `The active entity is ${credentials.entity_id}, not ${entityId}. Switch to it with ` +
        '`fam entity switch` so the key being vouched for comes from a key file on this ' +
        'machine rather than from the server.'
    );
  }
  const entityKeyFile: EncryptedKeyFile = JSON.parse(credentials.encrypted_key_file);

  const sequence = Number(flags.sequence ?? Date.now());

  const record = await mintVoucher({
    accountId: keyFile.entity_id,
    accountPrivateKey,
    entityId,
    entityPublicKey: entityKeyFile.public_key,
    sequence,
  });

  await apiRequest(config, '/vouchers/publish', { record });

  console.log(`Voucher published for ${entityId}.`);
  console.log(`  binds key: ${entityKeyFile.public_key.slice(0, 16)}…`);
  console.log(`  sequence:  ${record.sequence}`);
  console.log(`  expires:   ${record.expiresAt}`);
  console.log('');
  console.log('The record is stored. A peer can now VERIFY it — `fam history` and the MCP');
  console.log('adapter both resolve the chain — once two more things are true: your account');
  console.log('key is published at the path above, and that peer has run');
  console.log('`fam account trust <your-account> --github <you>` to pin it.');
}

async function inferAccountId(): Promise<string> {
  const credentials = await getActiveEntityCredentials();
  // `name@account` — the account is everything after the first '@'.
  const at = credentials.entity_id.indexOf('@');
  if (at === -1) {
    throw new Error(
      `Cannot infer an account from "${credentials.entity_id}". Pass --account explicitly.`
    );
  }
  return credentials.entity_id.slice(at + 1);
}

async function promptPasskey(): Promise<string> {
  const readline = await import('readline');
  const rl = readline.createInterface({ input: process.stdin, output: process.stderr });

  return new Promise((resolve) => {
    rl.question('Enter passkey for the account key: ', (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}


/**
 * Fetch a peer's account key from their forge and pin it locally.
 *
 * ⚠️ FIRST CONTACT IS TAKEN ON FAITH AND THE COMMAND SAYS SO. Trust-on-first-use
 * that does not tell the user it is trusting on first use is the identity-layer
 * version of a voucher nobody reads: the guarantee reads as stronger than it is,
 * and the moment where a person could have checked passes silently.
 *
 * ⚠️ AND A CHANGED KEY IS REFUSED, NOT ABSORBED. An attack and a legitimate
 * rotation produce the SAME observation; the entire value of pinning is that a
 * human is asked which one this is.
 */
async function trust(
  positional: string[],
  flags: Record<string, string | boolean>
): Promise<void> {
  const accountId = positional[0];
  const username = flags.github as string | undefined;

  if (!accountId || !username) {
    throw new Error('Usage: fam account trust <account_id> --github <username>');
  }

  const forge: Forge = 'github';
  const fetched = await fetchAccountKey({ forge, username }, fetch);

  if (flags['accept-change'] === true) {
    await acceptPeerAnchorChange(accountId, fetched.publicKey);
    console.log(`Pin for ${accountId} moved to the key now at their anchor.`);
    console.log(`  ${fetched.publicKey}`);
    return;
  }

  const observation = await observePeerAnchor({
    accountId,
    publicKey: fetched.publicKey,
    url: fetched.url,
  });

  switch (observation.status) {
    case 'pinned':
      console.log(`Pinned an account key for ${accountId}.`);
      console.log(`  ${observation.publicKey}`);
      console.log(`  from ${fetched.url}`);
      console.log('');
      console.log('⚠️  TAKEN ON FAITH. This is the first key seen for this peer, and nothing');
      console.log('    here proves the repository is theirs — only that whoever controls it');
      console.log('    has been consistent. Confirm the username out of band if it matters;');
      console.log('    a lookalike account is one glyph away and a key comparison is not.');
      console.log('    Every key AFTER this one is checked against this pin.');
      break;

    case 'unchanged':
      console.log(`${accountId}'s account key is unchanged.`);
      break;

    case 'changed':
      console.log(`⚠️  THE KEY AT ${accountId}'s ANCHOR HAS CHANGED. Nothing was updated.`);
      console.log('');
      console.log(`    pinned:   ${observation.pinned}`);
      console.log(`    observed: ${observation.observed}`);
      console.log('');
      console.log('    This is either a rotation they performed, or a substitution.');
      console.log('    The two look identical from here, which is why you are being asked.');
      console.log('    Confirm with them out of band, then re-run with --accept-change.');
      console.log('    Until then, verification keeps using the pinned key.');
      break;
  }
}
