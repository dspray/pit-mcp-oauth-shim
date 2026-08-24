import express from 'express';
import http from 'node:http';
import { mountOAuthShim, mountOAuthShimRaw } from './index.js';

const BASE = 'https://test-mcp.myprecisionit.com';
const app = express();
app.use(express.json()); // both real gateways mount this globally before the shim's routes
const { fixupTokenRedirectUri, ownCallbackUrl } = mountOAuthShim(app, {
  tenantId: 'TENANT123',
  clientId: 'CLIENT123',
  clientSecret: 'SECRET123',
  gatewayBaseUrl: BASE,
  entraScope: 'api://AUD123/mcp.access offline_access',
  resourceScopesSupported: ['api://AUD123/mcp.access'],
});

const server = app.listen(0, run);

function assert(cond, msg) {
  if (!cond) { console.error('FAIL:', msg); process.exitCode = 1; }
  else console.log('ok  :', msg);
}

async function run() {
  const port = server.address().port;
  const local = (path) => `http://127.0.0.1:${port}${path}`;

  // 1. PRM at both paths
  const prmRoot = await (await fetch(local('/.well-known/oauth-protected-resource'))).json();
  assert(prmRoot.resource === BASE, 'PRM root resource = self');
  const prmSuffixed = await (await fetch(local('/.well-known/oauth-protected-resource/mcp'))).json();
  assert(JSON.stringify(prmSuffixed) === JSON.stringify(prmRoot), 'PRM suffixed matches PRM root');

  // 2. ASM: issuer=self, registration_endpoint present and a string
  const asm = await (await fetch(local('/.well-known/oauth-authorization-server'))).json();
  assert(asm.issuer === BASE, 'ASM issuer = self, not Entra');
  assert(typeof asm.registration_endpoint === 'string' && asm.registration_endpoint.length > 0, 'registration_endpoint is a non-empty string');
  assert(asm.registration_endpoint === `${BASE}/register`, 'registration_endpoint points at /register');

  // 3. /register: fixed client_id, echoes requested redirect_uris, 201
  const regRes = await fetch(local('/register'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ redirect_uris: ['http://127.0.0.1:54321/callback'] }),
  });
  const reg = await regRes.json();
  assert(regRes.status === 201, '/register returns 201');
  assert(reg.client_id === 'CLIENT123', '/register returns the fixed client_id');
  assert(JSON.stringify(reg.redirect_uris) === JSON.stringify(['http://127.0.0.1:54321/callback']), '/register echoes requested redirect_uris');

  // 4. /authorize with a loopback redirect_uri: should swap to ownCallbackUrl + internal state, not the client's
  const authRes = await fetch(local('/authorize?response_type=code&client_id=whatever&redirect_uri=http%3A%2F%2F127.0.0.1%3A54321%2Fcallback&state=CLIENT_STATE_XYZ&code_challenge=abc&code_challenge_method=S256'), { redirect: 'manual' });
  assert(authRes.status === 302, '/authorize (loopback) returns a redirect');
  const authLoc = new URL(authRes.headers.get('location'));
  assert(authLoc.searchParams.get('redirect_uri') === ownCallbackUrl, '/authorize (loopback) sends Entra our OWN callback, not the caller\'s');
  assert(authLoc.searchParams.get('client_id') === 'CLIENT123', '/authorize (loopback) injects the real client_id');
  const internalState = authLoc.searchParams.get('state');
  assert(internalState !== 'CLIENT_STATE_XYZ', '/authorize (loopback) swaps state to an internal key, not the caller\'s state verbatim');

  // 5. /authorize with the fixed claude.ai callback: unchanged pass-through, no swap
  const authRes2 = await fetch(local('/authorize?response_type=code&client_id=whatever&redirect_uri=https%3A%2F%2Fclaude.ai%2Fapi%2Fmcp%2Fauth_callback&state=S2&code_challenge=abc&code_challenge_method=S256'), { redirect: 'manual' });
  const authLoc2 = new URL(authRes2.headers.get('location'));
  assert(authLoc2.searchParams.get('redirect_uri') === 'https://claude.ai/api/mcp/auth_callback', 'non-loopback /authorize leaves redirect_uri untouched (pass-through)');
  assert(authLoc2.searchParams.get('state') === 'S2', 'non-loopback /authorize leaves state untouched');

  // 6. Simulate Entra's callback hitting our /oauth/callback with the internal state
  const cbRes = await fetch(local(`/oauth/callback?code=FAKE_ENTRA_CODE&state=${internalState}`), { redirect: 'manual' });
  assert(cbRes.status === 302, '/oauth/callback redirects back to the caller');
  const cbLoc = new URL(cbRes.headers.get('location'));
  assert(cbLoc.origin + cbLoc.pathname === 'http://127.0.0.1:54321/callback', '/oauth/callback redirects to the ORIGINAL caller loopback redirect_uri');
  assert(cbLoc.searchParams.get('code') === 'FAKE_ENTRA_CODE', '/oauth/callback forwards the real Entra code');
  assert(cbLoc.searchParams.get('state') === 'CLIENT_STATE_XYZ', '/oauth/callback restores the caller\'s original state');
  assert(cbLoc.searchParams.get('iss') === BASE, '/oauth/callback sets iss per RFC 9207');

  // 7. Token redirect_uri fixup: a code that went through the loopback swap must
  //    get redirect_uri overridden back to ownCallbackUrl for the Entra /token call
  const fixedBody = fixupTokenRedirectUri({ code: 'FAKE_ENTRA_CODE', redirect_uri: 'http://127.0.0.1:54321/callback', grant_type: 'authorization_code' });
  assert(fixedBody.redirect_uri === ownCallbackUrl, 'fixupTokenRedirectUri overrides redirect_uri for a loopback-swapped code');

  // 8. Fixup is single-use: a second call for the same code must NOT still override (already consumed)
  const secondCall = fixupTokenRedirectUri({ code: 'FAKE_ENTRA_CODE', redirect_uri: 'http://127.0.0.1:54321/callback', grant_type: 'authorization_code' });
  assert(secondCall.redirect_uri === 'http://127.0.0.1:54321/callback', 'fixupTokenRedirectUri is single-use (no override on replay)');

  // 9. A code that never went through /authorize's loopback path is untouched
  const untouched = fixupTokenRedirectUri({ code: 'SOME_OTHER_CODE', redirect_uri: 'https://claude.ai/api/mcp/auth_callback' });
  assert(untouched.redirect_uri === 'https://claude.ai/api/mcp/auth_callback', 'fixupTokenRedirectUri leaves non-loopback codes untouched');

  // 10. Replaying a consumed /oauth/callback state fails cleanly (no crash, no redirect to nowhere)
  const replay = await fetch(local(`/oauth/callback?code=X&state=${internalState}`));
  assert(replay.status === 400, '/oauth/callback rejects a replayed/unknown state with 400, not a crash');

  server.close();

  await runCallbackPathOverride();
  await runAsyncCredentials();
  await runAsyncScope();
  await runRawAdapter();

  console.log(process.exitCode ? '\nSOME CHECKS FAILED' : '\nALL CHECKS PASSED');
}

// A gateway (github, procore, qbo) that already owns /oauth/callback for a
// second, unrelated OAuth flow must be able to put the shim's own callback
// somewhere else entirely.
async function runCallbackPathOverride() {
  const base = 'https://collide-mcp.myprecisionit.com';
  const app = express();
  app.use(express.json());
  let secondFlowHit = false;
  app.get('/oauth/callback', (_req, res) => { secondFlowHit = true; res.send('second flow, not ours'); });
  const { ownCallbackUrl } = mountOAuthShim(app, {
    tenantId: 'T', clientId: 'C', clientSecret: 'S', gatewayBaseUrl: base,
    entraScope: 'api://AUD/mcp.access', callbackPath: '/entra/oauth/callback',
  });
  assert(ownCallbackUrl === `${base}/entra/oauth/callback`, 'callbackPath override changes ownCallbackUrl');

  const server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  const port = server.address().port;
  const local = (p) => `http://127.0.0.1:${port}${p}`;

  const authRes = await fetch(local('/authorize?redirect_uri=http%3A%2F%2F127.0.0.1%3A1234%2Fcb&state=S1'), { redirect: 'manual' });
  const loc = new URL(authRes.headers.get('location'));
  assert(loc.searchParams.get('redirect_uri') === `${base}/entra/oauth/callback`, 'callbackPath override is used for the loopback swap, not the default /oauth/callback');

  const preExisting = await fetch(local('/oauth/callback'));
  assert(preExisting.status === 200 && secondFlowHit, 'the gateway\'s own pre-existing /oauth/callback route is untouched and still reachable');

  server.close();
}

// n8n/Ramp/Stripe resolve client_id/client_secret from Key Vault at request
// time rather than a static env var — the shim must support that.
async function runAsyncCredentials() {
  const base = 'https://kv-mcp.myprecisionit.com';
  const app = express();
  app.use(express.json());
  let secretFetches = 0;
  const getClientId = async () => { secretFetches++; return 'KV_CLIENT_ID'; };
  mountOAuthShim(app, {
    tenantId: 'T', clientId: getClientId, clientSecret: async () => 'KV_SECRET',
    gatewayBaseUrl: base, entraScope: 'api://AUD/mcp.access',
  });

  const server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  const port = server.address().port;
  const local = (p) => `http://127.0.0.1:${port}${p}`;

  const reg = await (await fetch(local('/register'), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })).json();
  assert(reg.client_id === 'KV_CLIENT_ID', '/register resolves an async clientId function');

  const authRes = await fetch(local('/authorize?redirect_uri=https%3A%2F%2Fclaude.ai%2Fapi%2Fmcp%2Fauth_callback&state=S'), { redirect: 'manual' });
  const loc = new URL(authRes.headers.get('location'));
  assert(loc.searchParams.get('client_id') === 'KV_CLIENT_ID', '/authorize resolves an async clientId function');
  assert(secretFetches === 2, 'async clientId resolver is called fresh per request, not cached at mount time (2 calls: register + authorize)');

  server.close();
}

// n8n/Ramp/Stripe build their Entra scope string FROM the async-resolved
// clientId (`${clientId}/mcp.access offline_access`) — entraScope itself
// must be allowed to be an async resolver too, not just a plain string.
async function runAsyncScope() {
  const base = 'https://kv-scope-mcp.myprecisionit.com';
  const app = express();
  app.use(express.json());
  const getClientId = async () => 'SCOPE_CLIENT_ID';
  mountOAuthShim(app, {
    tenantId: 'T', clientId: getClientId, clientSecret: async () => 'S',
    gatewayBaseUrl: base,
    entraScope: async () => `${await getClientId()}/mcp.access offline_access`,
    resourceScopesSupported: ['SCOPE_CLIENT_ID/mcp.access'],
  });

  const server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  const port = server.address().port;
  const local = (p) => `http://127.0.0.1:${port}${p}`;

  const authRes = await fetch(local('/authorize?redirect_uri=https%3A%2F%2Fclaude.ai%2Fapi%2Fmcp%2Fauth_callback&state=S'), { redirect: 'manual' });
  const loc = new URL(authRes.headers.get('location'));
  assert(loc.searchParams.get('scope') === 'SCOPE_CLIENT_ID/mcp.access offline_access', '/authorize resolves an async entraScope function derived from the async clientId');

  server.close();
}

// Mosyle has no express at all — raw Node http with a hand-rolled router.
async function runRawAdapter() {
  const base = 'https://raw-mcp.myprecisionit.com';
  const routes = [];
  const addRoute = (method, path, handler) => routes.push({ method, path, handler });
  const { ownCallbackUrl } = mountOAuthShimRaw(addRoute, {
    tenantId: 'T', clientId: 'C', clientSecret: 'S', gatewayBaseUrl: base,
    entraScope: 'api://AUD/mcp.access',
  });
  assert(ownCallbackUrl === `${base}/oauth/callback`, 'raw adapter computes the same ownCallbackUrl shape');

  const server = http.createServer(async (req, res) => {
    const path = new URL(req.url, 'http://internal').pathname;
    const route = routes.find((r) => r.method === req.method && r.path === path);
    if (!route) { res.writeHead(404); return res.end(); }
    if (req.method === 'POST') {
      const chunks = [];
      for await (const c of req) chunks.push(c);
      try { req._body = JSON.parse(Buffer.concat(chunks).toString() || '{}'); } catch { req._body = {}; }
    }
    route.handler(req, res);
  });
  await new Promise((r) => server.listen(0, r));
  const port = server.address().port;
  const local = (p) => `http://127.0.0.1:${port}${p}`;

  const prm = await (await fetch(local('/.well-known/oauth-protected-resource'))).json();
  assert(prm.resource === base, 'raw adapter: PRM served correctly');

  const reg = await (await fetch(local('/register'), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ redirect_uris: ['http://127.0.0.1:1/cb'] }) })).json();
  assert(reg.client_id === 'C' && JSON.stringify(reg.redirect_uris) === JSON.stringify(['http://127.0.0.1:1/cb']), 'raw adapter: /register works with req._body');

  const authRes = await fetch(local('/authorize?redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb&state=RS'), { redirect: 'manual' });
  assert(authRes.status === 302, 'raw adapter: /authorize redirects');
  const loc = new URL(authRes.headers.get('location'));
  const internalState = loc.searchParams.get('state');
  assert(loc.searchParams.get('redirect_uri') === ownCallbackUrl, 'raw adapter: loopback swap targets ownCallbackUrl');

  const cb = await fetch(local(`/oauth/callback?code=RAWCODE&state=${internalState}`), { redirect: 'manual' });
  const cbLoc = new URL(cb.headers.get('location'));
  assert(cbLoc.origin + cbLoc.pathname === 'http://127.0.0.1:9999/cb' && cbLoc.searchParams.get('code') === 'RAWCODE', 'raw adapter: callback redirects back to the caller with the real code');

  server.close();
}
