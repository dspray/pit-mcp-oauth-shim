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
// Entra app registration: `${gatewayBaseUrl}${callbackPath}` (callbackPath
// defaults to /oauth/callback — see opts.callbackPath below for gateways
// that already own that path for a second, unrelated OAuth flow). No new
// app, no group change.
//
// Two entry points:
//   - mountOAuthShim(app, opts)        — for an existing express app.
//   - mountOAuthShimRaw(addRoute, opts) — for a hand-rolled router (no
//     express) that registers routes as addRoute(method, path, handler) and
//     hands each handler a Node http.IncomingMessage/ServerResponse pair.
// Both are thin adapters over the same framework-agnostic core, so the
// actual OAuth logic exists exactly once regardless of how a given gateway
// is built (see D-001: fix once, not per-gateway).
//
// opts.clientId / opts.clientSecret may each be a plain string OR a
// () => Promise<string> — several gateways (n8n, Ramp, Stripe, ...) resolve
// these from Key Vault per-request rather than a static env var.
//
// Single-instance assumption: pending-authorization state lives in an
// in-memory Map. This is safe only because every gateway using this shim is
// pinned to minReplicas=1/maxReplicas=1 (confirmed in each gateway's
// main.bicep — check this before adopting on a new one). If a gateway ever
// scales beyond one replica, this state needs to move to a shared store.

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

async function resolveValue(v) {
  return typeof v === 'function' ? await v() : v;
}

// Reads a query param regardless of whether `query` is a plain object
// (express's req.query) or a URLSearchParams (raw-http adapters).
function getParam(query, name) {
  if (query instanceof URLSearchParams) return query.get(name);
  const v = query?.[name];
  return typeof v === 'string' ? v : undefined;
}

/**
 * Framework-agnostic core. Returns plain async functions that compute what
 * to respond with; callers (mountOAuthShim / mountOAuthShimRaw) are
 * responsible for actually writing an HTTP response.
 *
 * @param {object} opts
 * @param {string} opts.tenantId       Entra tenant GUID
 * @param {string|() => Promise<string>} opts.clientId      This gateway's Entra app (client) ID
 * @param {string|() => Promise<string>} opts.clientSecret  This gateway's Entra app client secret (only resolved by fixupTokenRedirectUri's caller, never read here directly)
 * @param {string} opts.gatewayBaseUrl This gateway's own https origin, no trailing slash
 * @param {string|() => Promise<string>} opts.entraScope  Full scope string sent to Entra, e.g. `api://<aud>/mcp.access offline_access`. May be a function when the scope string is derived from an async-resolved clientId (e.g. `` `${await getClientId()}/mcp.access` ``) — pass opts.resourceScopesSupported explicitly in that case, since it can't be derived from a function synchronously.
 * @param {string[]} [opts.resourceScopesSupported]  Scopes advertised in PRM/ASM (defaults to [entraScope's resource scope] when entraScope is a plain string; required if entraScope is a function)
 * @param {string} [opts.callbackPath] Path for the shim's own Entra callback (default '/oauth/callback'). Override when the gateway already owns that path for a different OAuth flow (e.g. GitHub's per-user App auth, Procore's, Intuit's).
 * @param {string} [opts.protectedResourceSuffix] Path suffix for RFC 9728's path-suffixed PRM form (default 'mcp', i.e. served at `/.well-known/oauth-protected-resource/mcp`).
 */
export function createOAuthShimCore(opts) {
  const { tenantId, clientId, clientSecret, gatewayBaseUrl, entraScope, resourceScopesSupported } = opts;
  const callbackPath = opts.callbackPath ?? '/oauth/callback';
  const protectedResourceSuffix = opts.protectedResourceSuffix ?? 'mcp';
  for (const [k, v] of Object.entries({ tenantId, clientId, clientSecret, gatewayBaseUrl, entraScope })) {
    if (!v) throw new Error(`createOAuthShimCore: opts.${k} is required`);
  }

  const entraBase = `https://login.microsoftonline.com/${tenantId}`;
  const scopesSupported = resourceScopesSupported
    ?? (typeof entraScope === 'string' ? [entraScope.split(' ')[0]] : []);
  const ownCallbackUrl = `${gatewayBaseUrl}${callbackPath}`;

  // stateKey -> { redirectUri, clientState, createdAt }  (consumed at the callback route)
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

  async function handleProtectedResource() {
    return protectedResourceMetadata;
  }

  async function handleAuthServerMetadata() {
    return {
      issuer: gatewayBaseUrl, // R3: the gateway is the authorization server the client sees
      authorization_endpoint: `${gatewayBaseUrl}/authorize`,
      token_endpoint: `${gatewayBaseUrl}/token`,
      registration_endpoint: `${gatewayBaseUrl}/register`, // R1/R7: always a string
      scopes_supported: scopesSupported,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      code_challenge_methods_supported: ['S256'],
    };
  }

  // RFC 7591 compatibility stub — mints nothing, persists nothing. Echoes
  // back whatever redirect_uris the caller asked for; real enforcement is
  // the loopback check in handleAuthorize below, not this response.
  async function handleRegister(body) {
    const id = await resolveValue(clientId);
    const requestedRedirectUris = Array.isArray(body?.redirect_uris) ? body.redirect_uris : [];
    return {
      status: 201,
      body: {
        client_id: id,
        redirect_uris: requestedRedirectUris,
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        token_endpoint_auth_method: 'none',
      },
    };
  }

  async function handleAuthorize(query) {
    const id = await resolveValue(clientId);
    const scope = await resolveValue(entraScope);
    const requestedRedirectUri = getParam(query, 'redirect_uri');
    const isLoopback = typeof requestedRedirectUri === 'string' && LOOPBACK_REDIRECT_RE.test(requestedRedirectUri);

    const params = new URLSearchParams(query);
    params.set('client_id', id);
    params.set('scope', scope);
    // RFC 8707 resource indicator conflicts with Entra v2's scope-derived
    // audience (AADSTS9010010) — strip it, same as before this module existed.
    params.delete('resource');

    if (!isLoopback) {
      // claude.ai's fixed web callback, or anything else not a loopback form:
      // unchanged pass-through behavior, exactly as before this module.
      return { redirectUrl: `${entraBase}/oauth2/v2.0/authorize?${params.toString()}` };
    }

    // Loopback: Entra only recognizes ownCallbackUrl as a registered redirect
    // for this app. Swap it in, remember the caller's real redirect_uri and
    // state, and hand back control at the callback route below.
    sweep(pendingAuthorize, PENDING_AUTHORIZE_TTL_MS);
    const stateKey = randomUUID();
    pendingAuthorize.set(stateKey, {
      redirectUri: requestedRedirectUri,
      clientState: getParam(query, 'state') ?? '',
      createdAt: Date.now(),
    });
    params.set('redirect_uri', ownCallbackUrl);
    params.set('state', stateKey);
    return { redirectUrl: `${entraBase}/oauth2/v2.0/authorize?${params.toString()}` };
  }

  function handleCallback(query) {
    const code = getParam(query, 'code');
    const state = getParam(query, 'state');
    const error = getParam(query, 'error');
    const errorDescription = getParam(query, 'error_description');

    const entry = pendingAuthorize.get(state);
    pendingAuthorize.delete(state);
    if (!entry) {
      return { status: 400, body: 'Authorization request expired or was not recognized. Please retry connecting.' };
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
    return { redirectUrl: out.toString() };
  }

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

  return {
    handleProtectedResource,
    handleAuthServerMetadata,
    handleRegister,
    handleAuthorize,
    handleCallback,
    fixupTokenRedirectUri,
    ownCallbackUrl,
    callbackPath,
    protectedResourceSuffixPath: `/.well-known/oauth-protected-resource/${protectedResourceSuffix}`,
  };
}

/** Mount the OAuth discovery + proxy shim on an existing express app. See createOAuthShimCore for opts. */
export function mountOAuthShim(app, opts) {
  const core = createOAuthShimCore(opts);

  app.get('/.well-known/oauth-protected-resource', async (_req, res) => {
    res.json(await core.handleProtectedResource());
  });
  app.get(core.protectedResourceSuffixPath, async (_req, res) => {
    res.json(await core.handleProtectedResource());
  });

  app.get('/.well-known/oauth-authorization-server', async (_req, res) => {
    res.json(await core.handleAuthServerMetadata());
  });

  app.post('/register', async (req, res) => {
    let body = req.body;
    if (typeof body === 'string') {
      try { body = JSON.parse(body); } catch { body = {}; }
    }
    const { status, body: respBody } = await core.handleRegister(body);
    res.status(status).json(respBody);
  });

  app.get('/authorize', async (req, res) => {
    const { redirectUrl } = await core.handleAuthorize(req.query);
    res.redirect(redirectUrl);
  });

  app.get(core.callbackPath, async (req, res) => {
    const result = await core.handleCallback(req.query);
    if (result.status) return res.status(result.status).send(result.body);
    res.redirect(result.redirectUrl);
  });

  return { fixupTokenRedirectUri: core.fixupTokenRedirectUri, ownCallbackUrl: core.ownCallbackUrl };
}

/**
 * Mount the shim on a hand-rolled router that isn't express — registers
 * routes via addRoute(method, path, (req, res) => ...) and expects each
 * handler to write the response itself against a raw Node
 * http.IncomingMessage/ServerResponse pair (Mosyle's pattern).
 *
 * @param {(method: string, path: string, handler: (req, res) => void) => void} addRoute
 * @param {object} opts  Same as createOAuthShimCore, plus:
 * @param {string} [opts.rawBodyKey] Property on `req` holding the already-parsed request body (default '_body').
 */
export function mountOAuthShimRaw(addRoute, opts) {
  const core = createOAuthShimCore(opts);
  const bodyKey = opts.rawBodyKey ?? '_body';

  const sendJson = (res, status, obj) => {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(obj));
  };
  const sendText = (res, status, text) => {
    res.writeHead(status, { 'Content-Type': 'text/plain' });
    res.end(text);
  };
  const sendRedirect = (res, url) => {
    res.writeHead(302, { Location: url });
    res.end();
  };
  const queryOf = (req) => new URL(req.url, 'http://internal').searchParams;

  addRoute('GET', '/.well-known/oauth-protected-resource', async (_req, res) => {
    sendJson(res, 200, await core.handleProtectedResource());
  });
  addRoute('GET', core.protectedResourceSuffixPath, async (_req, res) => {
    sendJson(res, 200, await core.handleProtectedResource());
  });

  addRoute('GET', '/.well-known/oauth-authorization-server', async (_req, res) => {
    sendJson(res, 200, await core.handleAuthServerMetadata());
  });

  addRoute('POST', '/register', async (req, res) => {
    const { status, body } = await core.handleRegister(req[bodyKey]);
    sendJson(res, status, body);
  });

  addRoute('GET', '/authorize', async (req, res) => {
    const { redirectUrl } = await core.handleAuthorize(queryOf(req));
    sendRedirect(res, redirectUrl);
  });

  addRoute('GET', core.callbackPath, async (req, res) => {
    const result = await core.handleCallback(queryOf(req));
    if (result.status) return sendText(res, result.status, result.body);
    sendRedirect(res, result.redirectUrl);
  });

  return { fixupTokenRedirectUri: core.fixupTokenRedirectUri, ownCallbackUrl: core.ownCallbackUrl };
}
