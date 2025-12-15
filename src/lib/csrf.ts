import { NextRequest } from 'next/server';
import crypto from 'crypto';

/**
 * Generate a CSRF token
 * @returns CSRF token string
 */
export function generateCsrfToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Verify CSRF token from request
 * @param request - NextRequest object
 * @param expectedToken - Expected CSRF token (from session)
 * @returns boolean indicating if token is valid
 */
export function verifyCsrfToken(
  request: NextRequest,
  expectedToken: string
): boolean {
  // Get token from header or body
  const headerToken = request.headers.get('x-csrf-token');

  if (!headerToken || !expectedToken) {
    return false;
  }

  // Constant-time comparison to prevent timing attacks
  return crypto.timingSafeEqual(
    Buffer.from(headerToken),
    Buffer.from(expectedToken)
  );
}

/**
 * CSRF protection middleware
 * Note: NextAuth v5 already provides CSRF protection for auth routes.
 * This utility is for custom API routes that need CSRF protection.
 *
 * Usage:
 * 1. Store CSRF token in session when rendering form
 * 2. Include token in form submissions via header: x-csrf-token
 * 3. Validate token using this function
 */
export function csrfProtection(
  request: NextRequest,
  sessionToken: string
): Response | null {
  // Only check CSRF for state-changing methods
  const method = request.method;
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
    return null;
  }

  // Verify CSRF token
  if (!verifyCsrfToken(request, sessionToken)) {
    return new Response(
      JSON.stringify({
        error: 'Invalid CSRF token',
        message: 'CSRF token validation failed',
      }),
      {
        status: 403,
        headers: {
          'Content-Type': 'application/json',
        },
      }
    );
  }

  return null;
}
