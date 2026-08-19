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
 */
export function storeChallenge(db: Database, entityId: string, nonce: string): void {
  const stmt = db.prepare(`
    INSERT OR REPLACE INTO challenges (entity_id, nonce, created_at)
    VALUES (?, ?, datetime('now'))
  `);
  
  stmt.run(entityId, nonce);
}

/**
 * Get and consume a challenge (single use, atomic).
 * Returns the challenge if valid, undefined otherwise.
 * Uses a transaction to prevent race conditions between concurrent authentications.
 */
export function consumeChallenge(db: Database, entityId: string): Challenge | undefined {
  // Use a transaction for atomicity: read + delete in one go
  const row = db.transaction(() => {
    const stmt = db.prepare(`
      SELECT * FROM challenges
      WHERE entity_id = ?
      AND created_at > datetime('now', '-' || ? || ' seconds')
    `);
    
    const row = stmt.get(entityId, NONCE_EXPIRY_SECONDS) as Challenge | undefined;
    
    if (row) {
      // Delete immediately (single use) — within same transaction
      const deleteStmt = db.prepare(`
        DELETE FROM challenges WHERE entity_id = ?
      `);
      deleteStmt.run(entityId);
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
