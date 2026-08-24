# pit-mcp-oauth-shim

Shared OAuth discovery + `/authorize`/`/register`/`/oauth/callback` proxy
logic for PrecisionIT's Entra-gated remote MCP gateways. One fix, many
gateways — see `pit-mcp-dcr-shim/context/decisions.md` D-001.

## What it fixes

D1-D4 / R1-R7 from `pit-mcp-dcr-shim/context/spec.md`:

- `registration_endpoint` published as a string, `/register` stub mints and
  persists nothing (R1, R2, R7).
- `issuer` is always the gateway's own origin (R3).
- Protected-resource metadata served at both well-known paths (R4).
- Loopback `redirect_uri` support — `http://127.0.0.1:<port>/...` and
  `http://localhost:<port>/...` — for Claude Code's local OAuth flow (R6).

## What it does NOT touch

Inbound JWT validation on `/mcp`, the access-group gate, the write-role gate,
and the two-stage confirm token all stay exactly as each gateway already
implements them. This module only speaks to the *outbound* leg (gateway →
Entra) of the authorization code flow. See spec.md's Non-goals.

## Required Entra app change

Add ONE new Web-platform redirect URI to the gateway's *existing* Entra app
registration — not a new app, not a new group:

```bash
az ad app update --id <existing-app-id> \
  --web-redirect-uris "https://claude.ai/api/mcp/auth_callback" "https://<gateway-host>/oauth/callback"
```

`az ad app update --web-redirect-uris` REPLACES the whole list, so include
the existing `claude.ai` callback alongside the new one or you will break the
claude.ai/Claude Desktop flow. Read the full current list back and diff it
before running this — don't assume the list above is complete for every app.

## Why a bare allowlist on `/authorize` isn't enough

Entra requires an exact-match registered redirect URI for Web-platform apps
— no port wildcarding. Its only loopback wildcard is a `publicClient`
redirect URI of the literal string `http://localhost` (no port), which
matches `localhost` only, never `127.0.0.1` — and Claude Code has moved to
`127.0.0.1`. So a naive pass-through `/authorize` that just forwards
whatever `redirect_uri` the client sent will get rejected by Entra itself for
any loopback caller, regardless of what this shim's own code does. This
module works around that by terminating the Entra leg at the gateway's own
already-registered `/oauth/callback` and re-redirecting the browser to the
caller's real loopback URL itself afterward — see `index.js`'s top comment
and `pit-mcp-dcr-shim/context/decisions.md` D-008 for the full reasoning.

## Usage (express)

```js
import express from 'express';
import { mountOAuthShim } from 'pit-mcp-oauth-shim';

const app = express();
const { fixupTokenRedirectUri } = mountOAuthShim(app, {
  tenantId: process.env.TENANT_ID,
  clientId: process.env.OAUTH_CLIENT_ID,
  clientSecret: process.env.OAUTH_CLIENT_SECRET,
  gatewayBaseUrl: process.env.GATEWAY_BASE_URL,
  entraScope: `api://${process.env.AUDIENCE}/mcp.access offline_access`,
});

// In your existing POST /token handler, before forwarding the body to Entra:
const body = fixupTokenRedirectUri(passthroughBodyFromClient);
```

The host gateway keeps its own `/token` handler (it already owns attaching
`client_secret` and calling Entra) — this module only corrects
`redirect_uri` on codes it issued via the loopback swap. Non-loopback token
exchanges (claude.ai's fixed callback) pass through `fixupTokenRedirectUri`
unchanged.

## Usage (no express — a hand-rolled router)

Some gateways (e.g. Mosyle) don't use express at all. `mountOAuthShimRaw`
adapts the same core logic to any router that registers routes as
`addRoute(method, path, handler)` and hands each handler a raw Node
`http.IncomingMessage`/`ServerResponse` pair:

```js
import { mountOAuthShimRaw } from 'pit-mcp-oauth-shim';

const { fixupTokenRedirectUri } = mountOAuthShimRaw(addRoute, {
  tenantId, clientId, clientSecret, gatewayBaseUrl, entraScope,
  rawBodyKey: '_body', // property on `req` holding the already-parsed body (default '_body')
});
```

## Credentials as a Key Vault resolver, not just an env var

`clientId` and `clientSecret` may each be a plain string OR an
`async () => string` — several gateways (n8n, Ramp, Stripe) fetch these from
Key Vault per-request rather than a static env var:

```js
mountOAuthShim(app, {
  clientId: () => getSecret('ramp-mcp-oauth-client-id'),
  clientSecret: () => getSecret('ramp-mcp-oauth-client-secret'),
  // ...
});
```

## Overriding the callback path

Some gateways already own `/oauth/callback` for a second, unrelated OAuth
flow — GitHub's per-user App auth, Procore's own API OAuth, Intuit's
per-company OAuth. Pass `callbackPath` to put the shim's own Entra callback
somewhere else, and register THAT path (not `/oauth/callback`) as the new
redirect URI in Entra:

```js
mountOAuthShim(app, {
  callbackPath: '/entra/oauth/callback',
  // ...
});
```

## Single-instance assumption

Pending-authorization state is an in-memory `Map`. Safe only because every
adopting gateway is pinned to `minReplicas: 1, maxReplicas: 1` in its
`main.bicep`. Confirm that before adopting this on a new gateway — if it
scales beyond one replica, this needs a shared store instead.
