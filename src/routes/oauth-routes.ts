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


// ── MCP OAuth 2.0 Server (for claude.ai connector) ─────────────────────────
import crypto from 'crypto';

// In-memory auth code store (single-user, short-lived)
const authCodes = new Map<string, number>(); // code -> expiry timestamp

/**
 * GET /oauth/authorize
 * claude.ai lands here to start the OAuth flow
 */
router.get('/authorize', (req: Request, res: Response) => {
  const { redirect_uri, state, code_challenge, code_challenge_method, response_type, client_id } = req.query as Record<string, string>;

  if (response_type !== 'code') {
    res.status(400).json({ error: 'unsupported_response_type' });
    return;
  }

  const html = `<!DOCTYPE html>
<html><head><title>Authorize GoHighLevel MCP</title>
<style>body{font-family:sans-serif;max-width:420px;margin:80px auto;padding:24px;text-align:center}
h2{margin-bottom:8px}p{color:#555;margin-bottom:24px}
.btn{background:#0066cc;color:#fff;padding:12px 28px;border:none;border-radius:6px;font-size:16px;cursor:pointer}</style>
</head><body>
<h2>GoHighLevel MCP</h2>
<p>Allow <strong>${client_id || 'Claude'}</strong> to access your GoHighLevel data?</p>
<form method="post" action="/oauth/authorize/approve">
  <input type="hidden" name="redirect_uri" value="${redirect_uri || ''}">
  <input type="hidden" name="state" value="${state || ''}">
  <input type="hidden" name="code_challenge" value="${code_challenge || ''}">
  <input type="hidden" name="code_challenge_method" value="${code_challenge_method || ''}">
  <button class="btn" type="submit">Authorize</button>
</form></body></html>`;
  res.send(html);
});

/**
 * POST /oauth/authorize/approve
 * User clicks Authorize → redirect back to claude.ai with code
 */
router.post('/authorize/approve', (req: Request, res: Response) => {
  const { redirect_uri, state } = req.body as Record<string, string>;

  if (!redirect_uri) {
    res.status(400).json({ error: 'missing redirect_uri' });
    return;
  }

  const code = crypto.randomBytes(32).toString('hex');
  authCodes.set(code, Date.now() + 5 * 60 * 1000); // 5-minute expiry

  const url = new URL(redirect_uri);
  url.searchParams.set('code', code);
  if (state) url.searchParams.set('state', state);

  res.redirect(url.toString());
});

/**
 * POST /oauth/token
 * claude.ai exchanges the code for an access token
 */
router.post('/token', (req: Request, res: Response) => {
  const { grant_type, code } = req.body as Record<string, string>;

  if (grant_type !== 'authorization_code') {
    res.status(400).json({ error: 'unsupported_grant_type' });
    return;
  }

  const expiry = authCodes.get(code);
  if (!expiry || Date.now() > expiry) {
    authCodes.delete(code);
    res.status(400).json({ error: 'invalid_grant' });
    return;
  }

  authCodes.delete(code); // single-use

  res.json({
    access_token: process.env.GHL_API_KEY,
    token_type: 'bearer',
    expires_in: 2592000, // 30 days
  });
});

export default router;
