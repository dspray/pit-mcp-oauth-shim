import express from 'express';
import { mountOAuthShim } from './index.js';

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
  console.log(process.exitCode ? '\nSOME CHECKS FAILED' : '\nALL CHECKS PASSED');
}
