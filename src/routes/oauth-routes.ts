/**
 * GoHighLevel OAuth 2.0 Routes
 *
 * GHL OAuth (for human login):
 *   GET  /oauth/login    – redirect user to GHL consent screen
 *   GET  /oauth/callback – exchange authorization code for access token
 *   POST /oauth/logout   – clear session
 *
 * MCP OAuth 2.0 server (for claude.ai connector):
 *   POST /oauth/register          – dynamic client registration (RFC 7591)
 *   GET  /oauth/authorize         – show approval page
 *   POST /oauth/authorize/approve – redirect back with auth code
 *   POST /oauth/token             – exchange code for access token
 */

import { Router, Request, Response } from 'express';
import axios from 'axios';
import { randomBytes } from 'crypto';

const router = Router();

// ── Environment variables ────────────────────────────────────────────────────
const GHL_CLIENT_ID     = process.env.GHL_OAUTH_CLIENT_ID     || '';
const GHL_CLIENT_SECRET = process.env.GHL_OAUTH_CLIENT_SECRET || '';
const GHL_REDIRECT_URI  = process.env.GHL_OAUTH_REDIRECT_URI  || '';
const GHL_AUTH_BASE     = 'https://marketplace.gohighlevel.com';
const GHL_TOKEN_URL     = 'https://services.leadconnectorhq.com/oauth/token';

// ── MCP OAuth state ──────────────────────────────────────────────────────────
// In-memory stores (single-user, process-scoped)
const registeredClients = new Map<string, string[]>(); // clientId -> redirect_uris
const authCodes         = new Map<string, number>();   // code     -> expiry ms

// ── Helpers ──────────────────────────────────────────────────────────────────

function missingEnvResponse(res: Response): void {
  res.status(500).json({
    error: 'Server misconfiguration',
    message: 'OAuth environment variables are not configured.',
  });
}

// ── MCP OAuth 2.0 server endpoints ──────────────────────────────────────────

/**
 * POST /oauth/register
 * Dynamic client registration (RFC 7591) — claude.ai calls this first.
 */
router.post('/register', (req: Request, res: Response) => {
  const clientId    = randomBytes(16).toString('hex');
  const redirectUris: string[] = req.body?.redirect_uris || [];
  registeredClients.set(clientId, redirectUris);
  console.log(`[MCP OAuth] Registered client: ${clientId}`);
  res.status(201).json({
    client_id:             clientId,
    client_id_issued_at:   Math.floor(Date.now() / 1000),
    redirect_uris:         redirectUris,
    grant_types:           ['authorization_code'],
    response_types:        ['code'],
    token_endpoint_auth_method: 'none',
  });
});

/**
 * GET /oauth/authorize
 * claude.ai redirects the user here to approve access.
 */
router.get('/authorize', (req: Request, res: Response) => {
  const { redirect_uri, state, code_challenge, code_challenge_method, response_type, client_id } = req.query as Record<string, string>;

  if (response_type !== 'code') {
    res.status(400).json({ error: 'unsupported_response_type' });
    return;
  }

  const html = `<!DOCTYPE html>
<html><head><title>Authorize GoHighLevel MCP</title>
<style>
  body { font-family: -apple-system, sans-serif; max-width: 420px; margin: 80px auto; padding: 24px; text-align: center; }
  h2   { margin-bottom: 8px; }
  p    { color: #555; margin-bottom: 28px; }
  .btn { background: #0066cc; color: #fff; padding: 12px 32px; border: none; border-radius: 6px; font-size: 16px; cursor: pointer; }
  .btn:hover { background: #0052a3; }
</style></head><body>
<h2>GoHighLevel MCP Server</h2>
<p>Allow <strong>${client_id || 'Claude'}</strong> to access your GoHighLevel data?</p>
<form method="post" action="/oauth/authorize/approve">
  <input type="hidden" name="redirect_uri"          value="${redirect_uri          || ''}">
  <input type="hidden" name="state"                 value="${state                 || ''}">
  <input type="hidden" name="code_challenge"        value="${code_challenge        || ''}">
  <input type="hidden" name="code_challenge_method" value="${code_challenge_method || ''}">
  <button class="btn" type="submit">Authorize</button>
</form></body></html>`;
  res.send(html);
});

/**
 * POST /oauth/authorize/approve
 * User clicked Authorize — generate code and redirect back to claude.ai.
 */
router.post('/authorize/approve', (req: Request, res: Response) => {
  const { redirect_uri, state } = req.body as Record<string, string>;

  if (!redirect_uri) {
    res.status(400).json({ error: 'missing redirect_uri' });
    return;
  }

  const code = randomBytes(32).toString('hex');
  authCodes.set(code, Date.now() + 5 * 60 * 1000); // 5-minute expiry

  const url = new URL(redirect_uri);
  url.searchParams.set('code', code);
  if (state) url.searchParams.set('state', state);

  console.log(`[MCP OAuth] Issued auth code, redirecting to ${redirect_uri}`);
  res.redirect(url.toString());
});

/**
 * POST /oauth/token
 * claude.ai exchanges the auth code for an access token.
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
    res.status(400).json({ error: 'invalid_grant', error_description: 'Authorization code expired or invalid.' });
    return;
  }

  authCodes.delete(code); // single-use

  console.log('[MCP OAuth] Token issued successfully');
  res.json({
    access_token: process.env.GHL_API_KEY,
    token_type:   'bearer',
    expires_in:   2592000, // 30 days
  });
});

// ── GHL OAuth routes ─────────────────────────────────────────────────────────

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
    redirect_uri:  GHL_REDIRECT_URI,
    client_id:     GHL_CLIENT_ID,
    scope: [
      'contacts.readonly', 'contacts.write',
      'conversations.readonly', 'conversations.write',
      'conversations/message.readonly', 'conversations/message.write',
      'locations.readonly',
      'locations/customFields.readonly', 'locations/customFields.write',
      'locations/customValues.readonly', 'locations/customValues.write',
      'locations/tags.readonly', 'locations/tags.write',
      'opportunities.readonly', 'opportunities.write',
      'calendars.readonly', 'calendars.write',
      'calendars/events.readonly', 'calendars/events.write',
      'blogs.readonly', 'blogs.write',
      'medias.readonly', 'medias.write',
      'surveys.readonly',
      'workflows.readonly',
      'products.readonly', 'products.write',
      'invoices.readonly', 'invoices.write',
    ].join(' '),
  });

  const authUrl = `${GHL_AUTH_BASE}/oauth/chooselocation?${params.toString()}`;
  console.log('[OAuth] Redirecting to GHL consent screen');
  res.redirect(authUrl);
});

/**
 * GET /oauth/callback
 * Handles the redirect from GHL after the user grants consent.
 */
router.get('/callback', async (req: Request, res: Response) => {
  const { code, error, error_description } = req.query as Record<string, string>;

  if (error) {
    res.status(400).json({ error: 'OAuth error', message: error_description || error });
    return;
  }

  if (!code) {
    res.status(400).json({ error: 'Bad request', message: 'Missing authorization code.' });
    return;
  }

  if (!GHL_CLIENT_ID || !GHL_CLIENT_SECRET || !GHL_REDIRECT_URI) {
    missingEnvResponse(res);
    return;
  }

  try {
    const tokenResponse = await axios.post(
      GHL_TOKEN_URL,
      new URLSearchParams({
        client_id:     GHL_CLIENT_ID,
        client_secret: GHL_CLIENT_SECRET,
        grant_type:    'authorization_code',
        code,
        redirect_uri:  GHL_REDIRECT_URI,
      }).toString(),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' } }
    );

    const { access_token, refresh_token, expires_in, locationId, companyId, userId } = tokenResponse.data;

    const session = req.session as typeof req.session & {
      accessToken?: string; refreshToken?: string; tokenExpiry?: number;
      userId?: string; locationId?: string; companyId?: string;
    };

    session.accessToken  = access_token;
    session.refreshToken = refresh_token;
    session.tokenExpiry  = Date.now() + expires_in * 1000;
    session.userId       = userId;
    session.locationId   = locationId;
    session.companyId    = companyId;

    console.log(`[OAuth] Authentication successful for user ${userId}, location ${locationId}`);
    res.redirect('/');
  } catch (err: any) {
    const status = err?.response?.status;
    const detail = err?.response?.data;
    console.error('[OAuth] Token exchange failed:', status, detail);
    res.status(502).json({ error: 'Token exchange failed', detail: detail || String(err) });
  }
});

/**
 * POST /oauth/logout
 */
router.post('/logout', (req: Request, res: Response) => {
  req.session.destroy((err) => {
    if (err) {
      res.status(500).json({ error: 'Logout failed', message: String(err) });
      return;
    }
    res.clearCookie('connect.sid');
    res.json({ success: true, message: 'Logged out successfully.' });
  });
});

export default router;