/**
 * GoHighLevel OAuth 2.0 Routes
 *
 * GET  /oauth/login    – redirect user to GHL consent screen
 * GET  /oauth/callback – exchange authorization code for access token
 * POST /oauth/logout   – clear session
 */

import { Router, Request, Response } from 'express';
import axios from 'axios';

const router = Router();

// ── Environment variables ────────────────────────────────────────────────────
const GHL_CLIENT_ID = process.env.GHL_OAUTH_CLIENT_ID || '';
const GHL_CLIENT_SECRET = process.env.GHL_OAUTH_CLIENT_SECRET || '';
const GHL_REDIRECT_URI = process.env.GHL_OAUTH_REDIRECT_URI || '';
const GHL_AUTH_BASE = 'https://marketplace.gohighlevel.com';
const GHL_TOKEN_URL = 'https://services.leadconnectorhq.com/oauth/token';

// ── Helpers ──────────────────────────────────────────────────────────────────

function missingEnvResponse(res: Response): void {
  res.status(500).json({
    error: 'Server misconfiguration',
    message:
      'OAuth environment variables are not configured. ' +
      'Set GHL_OAUTH_CLIENT_ID, GHL_OAUTH_CLIENT_SECRET, and GHL_OAUTH_REDIRECT_URI.',
  });
}

// ── Routes ───────────────────────────────────────────────────────────────────

/**
 * GET /oauth/login
 * Redirects the user to the GoHighLevel OAuth consent screen.
 */
router.get('/login', (req: Request, res: Response) => {
  if (!GHL_CLIENT_ID || !GHL_REDIRECT_URI) {
    missingEnvResponse(res);
    return;
  }

  const params = new URLSearchParams({
    response_type: 'code',
    redirect_uri: GHL_REDIRECT_URI,
    client_id: GHL_CLIENT_ID,
    scope: [
      'contacts.readonly',
      'contacts.write',
      'conversations.readonly',
      'conversations.write',
      'conversations/message.readonly',
      'conversations/message.write',
      'locations.readonly',
      'locations/customFields.readonly',
      'locations/customFields.write',
      'locations/customValues.readonly',
      'locations/customValues.write',
      'locations/tags.readonly',
      'locations/tags.write',
      'opportunities.readonly',
      'opportunities.write',
      'calendars.readonly',
      'calendars.write',
      'calendars/events.readonly',
      'calendars/events.write',
      'blogs.readonly',
      'blogs.write',
      'medias.readonly',
      'medias.write',
      'surveys.readonly',
      'workflows.readonly',
      'products.readonly',
      'products.write',
      'invoices.readonly',
      'invoices.write',
    ].join(' '),
  });

  const authUrl = `${GHL_AUTH_BASE}/oauth/chooselocation?${params.toString()}`;
  console.log(`[OAuth] Redirecting to GHL consent screen`);
  res.redirect(authUrl);
});

/**
 * GET /oauth/callback
 * Handles the redirect from GHL after the user grants consent.
 * Exchanges the authorization code for an access token and stores it in the session.
 */
router.get('/callback', async (req: Request, res: Response) => {
  const { code, error, error_description } = req.query as Record<string, string>;

  if (error) {
    console.error(`[OAuth] Callback error: ${error} – ${error_description}`);
    res.status(400).json({
      error: 'OAuth error',
      message: error_description || error,
    });
    return;
  }

  if (!code) {
    res.status(400).json({
      error: 'Bad request',
      message: 'Missing authorization code in callback.',
    });
    return;
  }

  if (!GHL_CLIENT_ID || !GHL_CLIENT_SECRET || !GHL_REDIRECT_URI) {
    missingEnvResponse(res);
    return;
  }

  try {
    console.log('[OAuth] Exchanging authorization code for access token...');

    const tokenResponse = await axios.post(
      GHL_TOKEN_URL,
      new URLSearchParams({
        client_id: GHL_CLIENT_ID,
        client_secret: GHL_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri: GHL_REDIRECT_URI,
      }).toString(),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json',
        },
      }
    );

    const {
      access_token,
      refresh_token,
      expires_in,
      locationId,
      companyId,
      userId,
    } = tokenResponse.data;

    // Persist token data in the session
    const session = req.session as typeof req.session & {
      accessToken?: string;
      refreshToken?: string;
      tokenExpiry?: number;
      userId?: string;
      locationId?: string;
      companyId?: string;
    };

    session.accessToken = access_token;
    session.refreshToken = refresh_token;
    // expires_in is in seconds; store absolute timestamp in ms
    session.tokenExpiry = Date.now() + expires_in * 1000;
    session.userId = userId;
    session.locationId = locationId;
    session.companyId = companyId;

    console.log(
      `[OAuth] ✅ Authentication successful for user ${userId}, location ${locationId}`
    );

    // Redirect to the root of the app after successful login
    res.redirect('/');
  } catch (err: any) {
    const status = err?.response?.status;
    const detail = err?.response?.data;
    console.error('[OAuth] Token exchange failed:', status, detail);
    res.status(502).json({
      error: 'Token exchange failed',
      message: 'Could not obtain an access token from GoHighLevel.',
      detail: detail || String(err),
    });
  }
});

/**
 * POST /oauth/logout
 * Destroys the session and clears the auth cookie.
 */
router.post('/logout', (req: Request, res: Response) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('[OAuth] Session destruction error:', err);
      res.status(500).json({ error: 'Logout failed', message: String(err) });
      return;
    }
    res.clearCookie('connect.sid');
    console.log('[OAuth] User logged out successfully');
    res.json({ success: true, message: 'Logged out successfully.' });
  });
});

export default router;
