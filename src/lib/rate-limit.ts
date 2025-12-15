import { NextRequest } from 'next/server';

interface RateLimitConfig {
  interval: number; // Time window in milliseconds
  maxRequests: number; // Maximum requests per interval
}

interface RateLimitRecord {
  count: number;
  resetTime: number;
}

// In-memory store for rate limiting
const rateLimitStore = new Map<string, RateLimitRecord>();

// Cleanup old entries every 10 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, record] of rateLimitStore.entries()) {
    if (record.resetTime < now) {
      rateLimitStore.delete(key);
    }
  }
}, 10 * 60 * 1000);

/**
 * Rate limiter function
 * @param identifier - Unique identifier (e.g., IP address or user ID)
 * @param config - Rate limit configuration
 * @returns Object with success status and remaining requests
 */
export function rateLimit(
  identifier: string,
  config: RateLimitConfig = { interval: 60000, maxRequests: 10 }
): {
  success: boolean;
  remaining: number;
  resetTime: number;
} {
  const now = Date.now();
  const record = rateLimitStore.get(identifier);

  // If no record exists or reset time has passed, create new record
  if (!record || record.resetTime < now) {
    const resetTime = now + config.interval;
    rateLimitStore.set(identifier, {
      count: 1,
      resetTime,
    });

    return {
      success: true,
      remaining: config.maxRequests - 1,
      resetTime,
    };
  }

  // Check if limit exceeded
  if (record.count >= config.maxRequests) {
    return {
      success: false,
      remaining: 0,
      resetTime: record.resetTime,
    };
  }

  // Increment count
  record.count++;
  rateLimitStore.set(identifier, record);

  return {
    success: true,
    remaining: config.maxRequests - record.count,
    resetTime: record.resetTime,
  };
}

/**
 * Get client identifier from request
 * @param request - NextRequest object
 * @returns Client identifier (IP or fallback)
 */
export function getClientIdentifier(request: NextRequest): string {
  // Try to get real IP from various headers
  const forwarded = request.headers.get('x-forwarded-for');
  const realIp = request.headers.get('x-real-ip');
  const cfConnectingIp = request.headers.get('cf-connecting-ip');

  // Use the first available IP
  const ip =
    cfConnectingIp ||
    realIp ||
    (forwarded ? forwarded.split(',')[0].trim() : null) ||
    'unknown';

  return ip;
}

/**
 * Rate limit middleware for API routes
 * @param request - NextRequest object
 * @param config - Rate limit configuration
 * @returns Response object if rate limited, null otherwise
 */
export function rateLimitMiddleware(
  request: NextRequest,
  config?: RateLimitConfig
) {
  const identifier = getClientIdentifier(request);
  const result = rateLimit(identifier, config);

  if (!result.success) {
    const retryAfter = Math.ceil((result.resetTime - Date.now()) / 1000);

    return new Response(
      JSON.stringify({
        error: 'Too many requests',
        message: 'Rate limit exceeded. Please try again later.',
        retryAfter,
      }),
      {
        status: 429,
        headers: {
          'Content-Type': 'application/json',
          'Retry-After': retryAfter.toString(),
          'X-RateLimit-Limit': config?.maxRequests.toString() || '10',
          'X-RateLimit-Remaining': '0',
          'X-RateLimit-Reset': result.resetTime.toString(),
        },
      }
    );
  }

  return null; // No rate limit response needed
}
