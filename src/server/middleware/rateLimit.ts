// Rate Limiting Middleware for FAM Server

import { FamError } from '../../types/errors';

// ============================================================================
// Types
// ============================================================================

interface RateLimitBucket {
  tokens: number;
  lastRefill: number;
}

interface RateLimitConfig {
  maxTokens: number;
  refillRate: number; // tokens per second
}

// ============================================================================
// Rate Limit Error
// ============================================================================

export class RateLimitError extends FamError {
  constructor(retryAfter: number) {
    super(`Rate limit exceeded. Retry after ${retryAfter} seconds`, 'RATE_LIMITED', 429);
    this.retryAfter = retryAfter;
  }
  
  public readonly retryAfter: number;
  
  override toJSON() {
    return {
      ...super.toJSON(),
      retry_after: this.retryAfter,
    };
  }
}

// ============================================================================
// Rate Limiter
// ============================================================================

export class RateLimiter {
  private buckets = new Map<string, RateLimitBucket>();
  private config: RateLimitConfig;
  private cleanupInterval: ReturnType<typeof setInterval> | null = null;
  
  constructor(config: RateLimitConfig) {
    this.config = config;
    
    // Cleanup old buckets every minute
    this.cleanupInterval = setInterval(() => this.cleanup(), 60 * 1000);
  }
  
  /**
   * Check if a request is allowed.
   * Returns true if allowed, throws RateLimitError if not.
   */
  check(key: string): boolean {
    const now = Date.now();
    const bucket = this.buckets.get(key);
    
    if (!bucket) {
      // First request - create bucket with full tokens
      this.buckets.set(key, {
        tokens: this.config.maxTokens - 1,
        lastRefill: now,
      });
      return true;
    }
    
    // Refill tokens based on time elapsed
    const elapsed = (now - bucket.lastRefill) / 1000;
    const refillAmount = elapsed * this.config.refillRate;
    bucket.tokens = Math.min(this.config.maxTokens, bucket.tokens + refillAmount);
    bucket.lastRefill = now;
    
    // Check if we have tokens
    if (bucket.tokens < 1) {
      const retryAfter = Math.ceil((1 - bucket.tokens) / this.config.refillRate);
      throw new RateLimitError(retryAfter);
    }
    
    // Consume a token
    bucket.tokens -= 1;
    return true;
  }
  
  /**
   * Get rate limit info for response headers.
   */
  getInfo(key: string): { remaining: number; reset: number } {
    const bucket = this.buckets.get(key);
    if (!bucket) {
      return {
        remaining: this.config.maxTokens,
        reset: Math.ceil(Date.now() / 1000) + 1,
      };
    }
    
    return {
      remaining: Math.floor(bucket.tokens),
      reset: Math.ceil(bucket.lastRefill / 1000) + 1,
    };
  }
  
  /**
   * Clean up old buckets (older than 5 minutes).
   */
  private cleanup(): void {
    const now = Date.now();
    const maxAge = 5 * 60 * 1000; // 5 minutes
    
    for (const [key, bucket] of this.buckets.entries()) {
      if (now - bucket.lastRefill > maxAge) {
        this.buckets.delete(key);
      }
    }
  }
  
  /**
   * Shutdown the rate limiter.
   */
  shutdown(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }
}

// ============================================================================
// Pre-configured Rate Limiters
// ============================================================================

/**
 * Per-entity rate limiter: 100 requests per minute.
 */
export const entityRateLimiter = new RateLimiter({
  maxTokens: 100,
  refillRate: 100 / 60, // ~1.67 tokens per second
});

/**
 * Per-IP rate limiter: 1000 requests per minute.
 */
export const ipRateLimiter = new RateLimiter({
  maxTokens: 1000,
  refillRate: 1000 / 60, // ~16.67 tokens per second
});

/**
 * Get client IP from request.
 */
export function getClientIp(req: Request): string {
  // Check for forwarded headers (behind proxy)
  const forwarded = req.headers.get('X-Forwarded-For');
  if (forwarded) {
    return forwarded.split(',')[0]?.trim() || 'unknown';
  }
  
  const realIp = req.headers.get('X-Real-IP');
  if (realIp) {
    return realIp;
  }
  
  // Fallback - in production, this would be the actual IP
  return 'unknown';
}
