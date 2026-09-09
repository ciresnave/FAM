// Challenge-Response Authentication for Entity Connection
//
// Flow:
// 1. Entity sends connect request with entity_id and public_key
// 2. Server generates random nonce and sends it to entity
// 3. Entity signs the nonce with its private key
// 4. Server verifies the signature against the stored public_key
// 5. If valid, entity is authenticated

import { Database } from 'bun:sqlite';
import { sign, verify, generateNonce, base64ToBuffer } from './keys';

// ============================================================================
// Types
// ============================================================================

export interface Challenge {
  entity_id: string;
  nonce: string; // base64-encoded
  created_at: string; // ISO timestamp
}

export interface ChallengeResponse {
  nonce: string; // base64-encoded
  signature: string; // base64-encoded
}

// ============================================================================
// Challenge Generation
// ============================================================================

const NONCE_EXPIRY_SECONDS = 5 * 60; // 5 minutes

/**
 * Generate a new challenge for entity authentication.
 */
export function generateChallenge(): { nonce: string } {
  return {
    nonce: generateNonce(32),
  };
}

// ============================================================================
// Database Operations
// ============================================================================

/**
 * Store a challenge in the database.
 *
 * ⚠️ MULTIPLE CHALLENGES MAY BE OUTSTANDING FOR ONE ENTITY, DELIBERATELY.
 * The table was keyed by `entity_id` alone until migration 20, so a second
 * `connect` REPLACED the first's nonce and both parties then failed to
 * authenticate — one told "Invalid signature" over a signature that was valid,
 * the other told "Challenge has expired" about a challenge seconds old. Two
 * instances of one entity are a supported situation, not an error.
 */
export function storeChallenge(db: Database, entityId: string, nonce: string): void {
  const stmt = db.prepare(`
    INSERT OR REPLACE INTO challenges (entity_id, nonce, created_at)
    VALUES (?, ?, datetime('now'))
  `);
  
  stmt.run(entityId, nonce);
}

/**
 * Get and consume ONE challenge — the one issued to `entityId` carrying
 * `nonce`. Single use, atomic. Returns undefined if there is no such live
 * challenge.
 *
 * ⚠️ THE NONCE IS PART OF THE LOOKUP, NOT ONLY OF THE VERIFICATION. Selecting
 * by `entity_id` alone consumed whichever challenge happened to be stored,
 * which after migration 20 could be a DIFFERENT INSTANCE'S — turning a second
 * instance's arrival into the first instance's authentication failure.
 *
 * ⚠️ AND BOTH COLUMNS MUST MATCH. Looking up by nonce alone would let a
 * holder of any valid nonce select the challenge it was issued to and
 * authenticate as its owner, because the route verifies against the key of the
 * entity NAMED IN THE REQUEST. The pair is the identity of a challenge.
 *
 * The transaction was here before and was never the problem: it made access to
 * one row atomic, correctly. The defect was that there could only ever BE one
 * row — a guard right about its own invariant, built on the wrong model.
 */
export function consumeChallenge(
  db: Database,
  entityId: string,
  nonce: string
): Challenge | undefined {
  // Use a transaction for atomicity: read + delete in one go
  const row = db.transaction(() => {
    const stmt = db.prepare(`
      SELECT * FROM challenges
      WHERE entity_id = ?
      AND nonce = ?
      AND created_at > datetime('now', '-' || ? || ' seconds')
    `);
    
    const row = stmt.get(entityId, nonce, NONCE_EXPIRY_SECONDS) as Challenge | undefined;
    
    if (row) {
      // Delete immediately (single use) — within same transaction, and scoped
      // to this challenge so a sibling instance's live challenge survives.
      const deleteStmt = db.prepare(`
        DELETE FROM challenges WHERE entity_id = ? AND nonce = ?
      `);
      deleteStmt.run(entityId, nonce);
    }
    
    return row;
  })();
  
  return row ?? undefined;
}

// ============================================================================
// Challenge-Response Flow
// ============================================================================

/**
 * Create a challenge response by signing the nonce with the private key.
 */
export async function createChallengeResponse(
  nonce: string,
  privateKeyBase64: string
): Promise<ChallengeResponse> {
  const nonceBytes = base64ToBuffer(nonce);
  const signature = await sign(nonceBytes, privateKeyBase64);
  
  return {
    nonce,
    signature,
  };
}

/**
 * Verify a challenge response against a public key.
 */
export async function verifyChallengeResponse(
  challenge: Challenge,
  response: ChallengeResponse,
  publicKeyBase64: string
): Promise<boolean> {
  // Check nonce matches
  if (challenge.nonce !== response.nonce) {
    return false;
  }
  
  // Verify signature
  const nonceBytes = base64ToBuffer(response.nonce);
  return verify(nonceBytes, response.signature, publicKeyBase64);
}

// ============================================================================
// Cleanup
// ============================================================================

/**
 * Clean up expired challenges.
 * Called periodically by the database cleanup interval.
 */
export function cleanupExpiredChallenges(db: Database): void {
  const stmt = db.prepare(`
    DELETE FROM challenges
    WHERE created_at < datetime('now', '-' || ? || ' seconds')
  `);
  
  stmt.run(NONCE_EXPIRY_SECONDS);
}
