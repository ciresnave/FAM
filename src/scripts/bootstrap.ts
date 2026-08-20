#!/usr/bin/env bun
/**
 * Create a local FAM account without OAuth.
 *
 *   bun run bootstrap you@example.com
 *
 * Prints an account token ONCE. Use it to create your first entity:
 *
 *   fam entity create <name>            (reads the token from ~/.fam/credentials.json)
 *
 * Runs against the database directly and is not reachable over HTTP — see the
 * note in src/auth/bootstrap.ts for why that is deliberate.
 */

import { getDatabaseContext, closeDatabase } from '../db';
import { bootstrapAccount } from '../auth/bootstrap';

const email = process.argv[2] ?? process.env.FAM_BOOTSTRAP_EMAIL;
const secret = process.env.FAM_SERVER_SECRET;

function fail(message: string): never {
  console.error(`error: ${message}`);
  process.exit(1);
}

if (!email) {
  fail('usage: bun run bootstrap <email>   (or set FAM_BOOTSTRAP_EMAIL)');
}

if (!secret) {
  fail(
    'FAM_SERVER_SECRET is not set. It is required to hash the account token, and ' +
      'it must be the SAME value the server runs with or the token will not validate. ' +
      'Copy .env.example to .env and set it.'
  );
}

try {
  const ctx = getDatabaseContext();
  const result = await bootstrapAccount(ctx, email, secret);

  console.log('');
  console.log(`  account   ${result.account_id}${result.created ? '' : '  (already existed)'}`);
  console.log(`  token     ${result.token}`);
  console.log('');
  console.log('  This token is shown once and is not recoverable — only its hash is stored.');
  console.log('  Re-running bootstrap issues a new token and invalidates this one.');
  console.log('');
} catch (e) {
  fail(e instanceof Error ? e.message : String(e));
} finally {
  closeDatabase();
}
