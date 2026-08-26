#!/usr/bin/env bun
/**
 * Re-encrypt stored messages onto the current server secret.
 *
 *   FAM_SERVER_SECRET=<new> FAM_SERVER_SECRET_PREVIOUS=<old> bun run rotate-key
 *
 * Rotation procedure:
 *   1. Move the existing FAM_SERVER_SECRET into FAM_SERVER_SECRET_PREVIOUS.
 *   2. Set FAM_SERVER_SECRET to the new secret.
 *   3. Run this. Every message is re-sealed with the new key.
 *   4. Only THEN remove the retired secret from FAM_SERVER_SECRET_PREVIOUS.
 *
 * Step 4 last, always. A retired secret dropped before this runs makes every
 * message still sealed with it permanently unreadable — which is why rotation
 * used to be documented as "don't".
 *
 * Idempotent: rows already on the current key are skipped, so an interrupted
 * run can simply be repeated.
 */

import { getDatabaseContext, closeDatabase } from '../db';
import {
  encryptMessage,
  decryptMessage,
  keyringFromEnv,
  keyIdFor,
} from '../crypto/message-encryption';

function fail(message: string): never {
  console.error(`error: ${message}`);
  process.exit(1);
}

const keyring = keyringFromEnv();

if (!keyring.current) fail('FAM_SERVER_SECRET is not set.');

if (process.env.FAM_ENCRYPT_MESSAGES !== 'true') {
  console.log('FAM_ENCRYPT_MESSAGES is not "true" — messages are stored as');
  console.log('plaintext and there is nothing to rotate.');
  process.exit(0);
}

const currentKid = await keyIdFor(keyring.current);
const ctx = getDatabaseContext();

// Read raw rows: getById() would decrypt, and this needs the stored envelope.
const rows = ctx.db.prepare('SELECT id, text FROM messages ORDER BY id').all() as Array<{
  id: number;
  text: string;
}>;

console.log('');
console.log(`  current key   ${currentKid}`);
console.log(`  retired keys  ${keyring.previous.length}`);
console.log(`  messages      ${rows.length}`);
console.log('');

let rotated = 0;
let alreadyCurrent = 0;
const failures: Array<{ id: number; reason: string }> = [];

const update = ctx.db.prepare('UPDATE messages SET text = ? WHERE id = ?');

for (const row of rows) {
  // Skip rows already sealed with the current key so reruns are cheap and an
  // interrupted rotation can be resumed.
  try {
    const envelope = JSON.parse(row.text) as { kid?: string };
    if (envelope?.kid === currentKid) {
      alreadyCurrent++;
      continue;
    }
  } catch {
    // Not an envelope — legacy raw bytes. Fall through and re-seal it.
  }

  try {
    const plaintext = await decryptMessage(row.text, keyring);
    const resealed = await encryptMessage(plaintext, keyring);
    update.run(resealed, row.id);
    rotated++;
  } catch (e) {
    failures.push({ id: row.id, reason: e instanceof Error ? e.message : String(e) });
  }
}

console.log(`  re-sealed     ${rotated}`);
console.log(`  already current ${alreadyCurrent}`);
console.log(`  failed        ${failures.length}`);

if (failures.length > 0) {
  console.log('');
  console.log('  Failures — these messages were NOT rotated and are still sealed');
  console.log('  with a key this server does not hold. Do not drop any retired');
  console.log('  secret until this is zero.');
  for (const f of failures.slice(0, 10)) {
    console.log(`    message ${f.id}: ${f.reason}`);
  }
  if (failures.length > 10) console.log(`    ... and ${failures.length - 10} more`);
}

console.log('');
if (failures.length === 0 && rotated > 0) {
  console.log('  Done. It is now safe to remove the retired secret from');
  console.log('  FAM_SERVER_SECRET_PREVIOUS.');
} else if (failures.length === 0) {
  console.log('  Nothing to do — every message is already on the current key.');
}
console.log('');

closeDatabase();
process.exit(failures.length === 0 ? 0 : 1);
