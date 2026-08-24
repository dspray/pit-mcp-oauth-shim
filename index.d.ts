export type MaybeAsync<T> = T | (() => Promise<T> | T);

export interface OAuthShimOpts {
  /** Entra tenant GUID */
  tenantId: string;
  /** This gateway's Entra app (client) ID — a literal string or an async resolver (e.g. Key Vault) */
  clientId: MaybeAsync<string>;
  /** This gateway's Entra app client secret — a literal string or an async resolver (e.g. Key Vault) */
  clientSecret: MaybeAsync<string>;
  /** This gateway's own https origin, no trailing slash */
  gatewayBaseUrl: string;
  /** Full scope string sent to Entra, e.g. `api://<aud>/mcp.access offline_access` — may be async if derived from an async-resolved clientId */
  entraScope: MaybeAsync<string>;
  /** Scopes advertised in PRM/ASM. Required if entraScope is a function (can't be derived synchronously otherwise). */
  resourceScopesSupported?: string[];
  /** Path for the shim's own Entra callback (default '/oauth/callback'). Override when the gateway already owns that path for a different OAuth flow. */
  callbackPath?: string;
  /** Path suffix for RFC 9728's path-suffixed PRM form (default 'mcp'). */
  protectedResourceSuffix?: string;
}

export interface OAuthShimHandle {
  /** Fixes up a /token request body's redirect_uri for codes issued via the loopback swap. Pass through the body you're about to forward to Entra's /token endpoint. */
  fixupTokenRedirectUri(body: Record<string, unknown>): Record<string, unknown>;
  /** This gateway's own Entra callback URL (gatewayBaseUrl + callbackPath). */
  ownCallbackUrl: string;
}

export interface OAuthShimCore extends OAuthShimHandle {
  handleProtectedResource(): Promise<Record<string, unknown>>;
  handleAuthServerMetadata(): Promise<Record<string, unknown>>;
  handleRegister(body: unknown): Promise<{ status: number; body: Record<string, unknown> }>;
  handleAuthorize(query: unknown): Promise<{ redirectUrl: string }>;
  handleCallback(query: unknown): { redirectUrl: string } | { status: number; body: string };
  callbackPath: string;
  protectedResourceSuffixPath: string;
}

/** Framework-agnostic core — see mountOAuthShim / mountOAuthShimRaw for the two adapters. */
export function createOAuthShimCore(opts: OAuthShimOpts): OAuthShimCore;

/** Mount the OAuth discovery + proxy shim on an existing express app (or express.Router()). */
export function mountOAuthShim(app: any, opts: OAuthShimOpts): OAuthShimHandle;

/**
 * Mount the shim on a hand-rolled router that isn't express — registers
 * routes via addRoute(method, path, (req, res) => void) and expects each
 * handler to write the response itself against a raw Node
 * http.IncomingMessage/ServerResponse pair.
 */
export function mountOAuthShimRaw(
  addRoute: (method: string, path: string, handler: (req: any, res: any) => void) => void,
  opts: OAuthShimOpts & { rawBodyKey?: string }
): OAuthShimHandle;
