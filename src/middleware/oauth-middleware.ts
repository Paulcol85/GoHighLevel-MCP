/**
 * GoHighLevel OAuth 2.0 Authentication Middleware
 * Validates OAuth tokens on protected endpoints
 */

import { Request, Response, NextFunction } from 'express';
import axios from 'axios';

// Extend Express session type to include our OAuth data
declare module 'express-session' {
  interface SessionData {
    accessToken?: string;
    tokenExpiry?: number;
    userId?: string;
    locationId?: string;
    companyId?: string;
  }
}

const GHL_BASE_URL = process.env.GHL_BASE_URL || 'https://services.leadconnectorhq.com';

/**
 * Validate an OAuth access token against the GHL API
 */
async function validateToken(token: string): Promise<boolean> {
  try {
    const response = await axios.get(`${GHL_BASE_URL}/oauth/locationToken`, {
      headers: {
        Authorization: `Bearer ${token}`,
        Version: '2021-07-28',
      },
      // Don't throw on 4xx — we handle it ourselves
      validateStatus: (status) => status < 500,
    });
    return response.status === 200;
  } catch (err) {
    console.error('[OAuth] Token validation request failed:', err);
    return false;
  }
}

/**
 * Extract bearer token from Authorization header
 */
function extractBearerToken(req: Request): string | null {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7).trim();
  }
  return null;
}

/**
 * Middleware: require a valid GHL OAuth token.
 *
 * Checks (in order):
 *  1. Authorization: Bearer <token> header
 *  2. Session-stored access token (set after /oauth/callback)
 *
 * Returns 401 JSON if neither is present or the token is invalid.
 */
export async function requireOAuth(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  // 1. Try Authorization header first (useful for API / MCP clients)
    const headerToken = extractBearerToken(req);
  if (headerToken) {
    const apiKey = process.env.GHL_API_KEY;
    if (apiKey && headerToken === apiKey) {
      res.locals.accessToken = headerToken;
      return next();
    }
    const valid = await validateToken(headerToken);
    if (valid) {
      // Attach token to request locals for downstream use
      res.locals.accessToken = headerToken;
      return next();
    }
    res.status(401).json({
      error: 'Unauthorized',
      message: 'The provided Bearer token is invalid or has expired.',
      loginUrl: '/oauth/login',
    });
    return;
  }

  // 2. Try session-stored token
  const session = req.session as Express.Request['session'] & {
    accessToken?: string;
    tokenExpiry?: number;
  };

  if (session.accessToken) {
    // Check local expiry first (avoid unnecessary network call)
    if (session.tokenExpiry && Date.now() > session.tokenExpiry) {
      session.destroy(() => {});
      res.status(401).json({
        error: 'Unauthorized',
        message: 'Your session has expired. Please log in again.',
        loginUrl: '/oauth/login',
      });
      return;
    }

    const valid = await validateToken(session.accessToken);
    if (valid) {
      res.locals.accessToken = session.accessToken;
      return next();
    }

    // Token invalid — clear the session
    session.destroy(() => {});
    res.status(401).json({
      error: 'Unauthorized',
      message: 'Your session token is no longer valid. Please log in again.',
      loginUrl: '/oauth/login',
    });
    return;
  }

  // 3. No token found at all
  res.status(401).json({
    error: 'Unauthorized',
    message:
      'Authentication required. Provide a Bearer token in the Authorization header or log in via /oauth/login.',
    loginUrl: '/oauth/login',
  });
}
