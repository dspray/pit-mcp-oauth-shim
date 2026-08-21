// Shared OAuth discovery + proxy shim for PrecisionIT Entra-gated MCP gateways.
//
// Fixes, fleet-wide once adopted (see pit-mcp-dcr-shim/context/spec.md R1-R7):
//   - Publishes registration_endpoint (a string, never null/absent) and a
//     /register stub that mints nothing and persists nothing — every caller
//     gets the same pre-registered client_id. The client_id is a public
//     identifier, not a credential; every real control (user auth, app-role
//     assignment, access-group membership, write-role gate) sits behind it,
//     unchanged, in the host gateway's own JWT validation.
//   - issuer is always the gateway's own origin, matching RFC 8414 (the
//     gateway, not Entra, is the authorization server the client talks to).
//   - Protected-resource metadata (RFC 9728) is served at both the root
//     well-known path and the path-suffixed form under /mcp.
//   - /authorize supports loopback redirect_uri forms (127.0.0.1 and
//     localhost, any port) by terminating the Entra leg at THIS gateway's
//     own already-registered callback and re-redirecting the browser back to
//     the caller's real loopback URL itself. Entra requires an exact-match
//     registered redirect URI and has no port-wildcarding for 127.0.0.1, so a
//     bare allowlist check on the incoming redirect_uri is not sufficient —
//     see pit-mcp-dcr-shim/context/decisions.md D-008 for why this shape was
//     chosen. Non-loopback callers (claude.ai's fixed web callback) are
//     untouched: same pass-through behavior as before, zero regression risk.
//
// Requires ONE new Web-platform redirect URI added to the gateway's existing
// Entra app registration: `${gatewayBaseUrl}/oauth/callback`. No new app, no
// group change.
//
// Single-instance assumption: pending-authorization state lives in an
// in-memory Map. This is safe only because every gateway using this shim is
// pinned to minReplicas=1/maxReplicas=1 (confirmed for unifi and crosswalk in
// their main.bicep). If a gateway ever scales beyond one replica, this state
// needs to move to a shared store (e.g. the gateway's own Supabase/Key Vault
// backing) before adopting this module.

import { randomUUID } from 'node:crypto';

const LOOPBACK_REDIRECT_RE = /^https?:\/\/(127\.0\.0\.1|localhost)(:\d+)?(\/|$)/i;
const PENDING_AUTHORIZE_TTL_MS = 10 * 60 * 1000; // generous: a human completing an Entra login
const PENDING_TOKEN_FIXUP_TTL_MS = 5 * 60 * 1000; // Entra auth codes are short-lived

function sweep(map, ttlMs) {
  const cutoff = Date.now() - ttlMs;
  for (const [key, entry] of map) {
    if (entry.createdAt < cutoff) map.delete(key);
  }
}

/**
 * Mount the OAuth discovery + proxy shim on an existing express app.
 *
 * @param {import('express').Express} app
 * @param {object} opts
 * @param {string} opts.tenantId            Entra tenant GUID
 * @param {string} opts.clientId            This gateway's Entra app (client) ID
 * @param {string} opts.clientSecret        This gateway's Entra app client secret
 * @param {string} opts.gatewayBaseUrl      This gateway's own https origin, no trailing slash
 * @param {string} opts.entraScope          Full scope string sent to Entra, e.g. `api://<aud>/mcp.access offline_access`
 * @param {string[]} [opts.resourceScopesSupported]  Scopes advertised in PRM/ASM (defaults to [entraScope's resource scope])
 */
export function mountOAuthShim(app, opts) {
  const { tenantId, clientId, clientSecret, gatewayBaseUrl, entraScope, resourceScopesSupported } = opts;
  for (const [k, v] of Object.entries({ tenantId, clientId, clientSecret, gatewayBaseUrl, entraScope })) {
    if (!v) throw new Error(`mountOAuthShim: opts.${k} is required`);
  }

  const entraBase = `https://login.microsoftonline.com/${tenantId}`;
  const scopesSupported = resourceScopesSupported ?? [entraScope.split(' ')[0]];
  const ownCallbackUrl = `${gatewayBaseUrl}/oauth/callback`;

  // stateKey -> { redirectUri, clientState, createdAt }  (consumed at /oauth/callback)
  const pendingAuthorize = new Map();
  // Entra auth code -> { createdAt }  (consumed at /token; presence alone means
  // "this code was issued against ownCallbackUrl, override redirect_uri")
  const pendingTokenFixup = new Map();

  const protectedResourceMetadata = {
    resource: gatewayBaseUrl,
    authorization_servers: [gatewayBaseUrl],
    scopes_supported: scopesSupported,
    bearer_methods_supported: ['header'],
  };
  app.get('/.well-known/oauth-protected-resource', (_req, res) => {
    res.json(protectedResourceMetadata);
  });
  // Path-suffixed form (RFC 9728) for the /mcp resource — every gateway on
  // this fleet serves MCP at /mcp, so the suffix is fixed.
  app.get('/.well-known/oauth-protected-resource/mcp', (_req, res) => {
    res.json(protectedResourceMetadata);
  });

  app.get('/.well-known/oauth-authorization-server', (_req, res) => {
    res.json({
      issuer: gatewayBaseUrl, // R3: the gateway is the authorization server the client sees
      authorization_endpoint: `${gatewayBaseUrl}/authorize`,
      token_endpoint: `${gatewayBaseUrl}/token`,
      registration_endpoint: `${gatewayBaseUrl}/register`, // R1/R7: always a string
      scopes_supported: scopesSupported,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      code_challenge_methods_supported: ['S256'],
    });
  });

  // RFC 7591 compatibility stub — mints nothing, persists nothing. Echoes
  // back whatever redirect_uris the caller asked for; real enforcement is
  // the loopback check in /authorize below, not this response.
  app.post('/register', (req, res) => {
    let body = req.body;
    if (typeof body === 'string') {
      try { body = JSON.parse(body); } catch { body = {}; }
    }
    const requestedRedirectUris = Array.isArray(body?.redirect_uris) ? body.redirect_uris : [];
    res.status(201).json({
      client_id: clientId,
      redirect_uris: requestedRedirectUris,
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
    });
  });

  app.get('/authorize', (req, res) => {
    const requestedRedirectUri = req.query.redirect_uri;
    const isLoopback = typeof requestedRedirectUri === 'string' && LOOPBACK_REDIRECT_RE.test(requestedRedirectUri);

    const params = new URLSearchParams(req.query);
    params.set('client_id', clientId);
    params.set('scope', entraScope);
    // RFC 8707 resource indicator conflicts with Entra v2's scope-derived
    // audience (AADSTS9010010) — strip it, same as before this module existed.
    params.delete('resource');

    if (!isLoopback) {
      // claude.ai's fixed web callback, or anything else not a loopback form:
      // unchanged pass-through behavior, exactly as before this module.
      return res.redirect(`${entraBase}/oauth2/v2.0/authorize?${params.toString()}`);
    }

    // Loopback: Entra only recognizes ownCallbackUrl as a registered redirect
    // for this app. Swap it in, remember the caller's real redirect_uri and
    // state, and hand back control at /oauth/callback below.
    sweep(pendingAuthorize, PENDING_AUTHORIZE_TTL_MS);
    const stateKey = randomUUID();
    pendingAuthorize.set(stateKey, {
      redirectUri: requestedRedirectUri,
      clientState: typeof req.query.state === 'string' ? req.query.state : '',
      createdAt: Date.now(),
    });
    params.set('redirect_uri', ownCallbackUrl);
    params.set('state', stateKey);
    res.redirect(`${entraBase}/oauth2/v2.0/authorize?${params.toString()}`);
  });

  app.get('/oauth/callback', (req, res) => {
    const { code, state, error, error_description: errorDescription } = req.query;
    const entry = pendingAuthorize.get(state);
    pendingAuthorize.delete(state);
    if (!entry) {
      return res.status(400).send('Authorization request expired or was not recognized. Please retry connecting.');
    }

    const out = new URL(entry.redirectUri);
    if (error) {
      out.searchParams.set('error', String(error));
      if (errorDescription) out.searchParams.set('error_description', String(errorDescription));
    } else {
      sweep(pendingTokenFixup, PENDING_TOKEN_FIXUP_TTL_MS);
      pendingTokenFixup.set(String(code), { createdAt: Date.now() });
      out.searchParams.set('code', String(code));
    }
    if (entry.clientState) out.searchParams.set('state', entry.clientState);
    out.searchParams.set('iss', gatewayBaseUrl); // RFC 9207 mix-up hardening
    res.redirect(out.toString());
  });

  // Wraps the host gateway's existing /token handler. The host still owns
  // the actual fetch to Entra's /token and its own response handling; this
  // only fixes up redirect_uri for codes issued via the loopback swap above,
  // since Entra requires redirect_uri to match between the /authorize and
  // /token legs of the SAME code.
  function fixupTokenRedirectUri(body) {
    const code = body?.code;
    if (code && pendingTokenFixup.has(String(code))) {
      pendingTokenFixup.delete(String(code));
      return { ...body, redirect_uri: ownCallbackUrl };
    }
    return body;
  }

  return { fixupTokenRedirectUri, ownCallbackUrl };
}
