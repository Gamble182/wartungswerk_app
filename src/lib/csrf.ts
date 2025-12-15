import { NextRequest, NextResponse } from 'next/server';
import crypto from 'crypto';

const CSRF_TOKEN_COOKIE = 'csrf-token';
const CSRF_TOKEN_HEADER = 'x-csrf-token';
const CSRF_TOKEN_LENGTH = 32;

/**
 * Generate a CSRF token using Double Submit Cookie pattern
 * @returns CSRF token string
 */
export function generateCsrfToken(): string {
  return crypto.randomBytes(CSRF_TOKEN_LENGTH).toString('base64');
}

/**
 * Set CSRF token in response cookies
 * @param response - NextResponse object
 * @param token - CSRF token to set
 */
export function setCsrfTokenCookie(
  response: NextResponse,
  token: string
): void {
  response.cookies.set(CSRF_TOKEN_COOKIE, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/',
    maxAge: 60 * 60 * 24, // 24 hours
  });
}

/**
 * Get CSRF token from request cookies
 * @param request - NextRequest object
 * @returns CSRF token or null
 */
export function getCsrfTokenFromCookie(request: NextRequest): string | null {
  return request.cookies.get(CSRF_TOKEN_COOKIE)?.value || null;
}

/**
 * Get CSRF token from request header
 * @param request - NextRequest object
 * @returns CSRF token or null
 */
export function getCsrfTokenFromHeader(request: NextRequest): string | null {
  return request.headers.get(CSRF_TOKEN_HEADER);
}

/**
 * Validate CSRF token using Double Submit Cookie pattern
 * @param request - NextRequest object
 * @returns true if valid, false otherwise
 */
export function validateCsrfToken(request: NextRequest): boolean {
  const tokenFromCookie = getCsrfTokenFromCookie(request);
  const tokenFromHeader = getCsrfTokenFromHeader(request);

  // Both tokens must exist and match
  if (!tokenFromCookie || !tokenFromHeader) {
    return false;
  }

  // Ensure both tokens are the same length before comparison
  if (tokenFromCookie.length !== tokenFromHeader.length) {
    return false;
  }

  // Constant-time comparison to prevent timing attacks
  try {
    return crypto.timingSafeEqual(
      Buffer.from(tokenFromCookie),
      Buffer.from(tokenFromHeader)
    );
  } catch {
    return false;
  }
}

/**
 * CSRF protection middleware for API routes using Double Submit Cookie pattern
 * Note: NextAuth v5 already provides CSRF protection for auth routes.
 * This utility is for custom API routes that need CSRF protection.
 *
 * Usage:
 * 1. Generate and set CSRF token cookie on initial page load or auth
 * 2. Client includes token in request header: x-csrf-token
 * 3. Middleware validates cookie matches header
 *
 * @param request - NextRequest object
 * @returns Response object if validation fails, null otherwise
 */
export function csrfProtection(request: NextRequest): Response | null {
  const method = request.method.toUpperCase();

  // Only check CSRF for state-changing methods
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    if (!validateCsrfToken(request)) {
      return new Response(
        JSON.stringify({
          error: 'CSRF validation failed',
          message: 'Invalid or missing CSRF token',
        }),
        {
          status: 403,
          headers: {
            'Content-Type': 'application/json',
          },
        }
      );
    }
  }

  return null; // No CSRF error
}

/**
 * Generate and set a new CSRF token for a response
 * @param response - NextResponse object
 * @returns The generated token
 */
export function setNewCsrfToken(response: NextResponse): string {
  const token = generateCsrfToken();
  setCsrfTokenCookie(response, token);
  return token;
}
