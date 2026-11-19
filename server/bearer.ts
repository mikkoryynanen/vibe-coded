import { createPublicKey, type JsonWebKeyInput, type KeyObject, verify } from 'node:crypto';

export const MCP_SCOPE_NAME = 'Bookings.ReadWrite';
const SKEW_S = 60;
const MAX_TOKEN_AGE_S = 15 * 60;
const JWKS_REFETCH_MS = 60_000;

type BearerConfig = { issuer: string; clientId: string; jwksUri: () => Promise<string | undefined> };

const part = (s: string) => JSON.parse(Buffer.from(s, 'base64url').toString()) as unknown;
const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

/** Entra endpoints are always https; plain http only for a local mock provider. */
export function httpsOrLocal(uri: string) {
  const { protocol, hostname } = new URL(uri);
  return protocol === 'https:' || (protocol === 'http:' && (hostname === 'localhost' || hostname === '127.0.0.1'));
}

/** Validates Entra v2 access tokens for /mcp. Throws an Error whose message is the reason (for the server log only). */
export function createBearerAuth(cfg: BearerConfig) {
  const jwks = { keys: new Map<string, KeyObject>(), fetchedAt: 0 };
  let fetching: Promise<void> | undefined;

  async function fetchKeys() {
    const uri = await cfg.jwksUri();
    if (!uri) throw new Error('Issuer metadata has no jwks_uri');
    if (!httpsOrLocal(uri)) throw new Error('jwks_uri must be https');
    jwks.fetchedAt = Date.now();
    const res = await fetch(uri, { signal: AbortSignal.timeout(5000) });
    if (!res.ok) throw new Error(`JWKS fetch failed with ${res.status}`);
    const body = (await res.json()) as { keys?: unknown };
    const keys = new Map<string, KeyObject>();
    for (const jwk of Array.isArray(body.keys) ? body.keys : []) {
      if (!isObject(jwk) || jwk.kty !== 'RSA' || typeof jwk.kid !== 'string' || (jwk.use !== undefined && jwk.use !== 'sig')) continue;
      try {
        keys.set(jwk.kid, createPublicKey({ key: jwk as JsonWebKeyInput['key'], format: 'jwk' }));
      } catch {}
    }
    jwks.keys = keys;
  }

  async function key(kid: string) {
    if (!jwks.keys.has(kid) && Date.now() - jwks.fetchedAt >= JWKS_REFETCH_MS) {
      fetching ??= fetchKeys().finally(() => { fetching = undefined; });
      await fetching;
    }
    const k = jwks.keys.get(kid);
    if (!k) throw new Error('Unknown signing key');
    return k;
  }

  return async function verifyToken(token: string): Promise<Record<string, unknown>> {
    const [h, p, sig, ...rest] = token.split('.');
    if (!h || !p || !sig || rest.length) throw new Error('Malformed token');
    let header: unknown;
    let claims: unknown;
    try {
      header = part(h);
      claims = part(p);
    } catch {
      throw new Error('Malformed token');
    }
    if (!isObject(header) || !isObject(claims)) throw new Error('Malformed token');
    if (header.alg !== 'RS256' || typeof header.kid !== 'string') throw new Error('Unsupported token algorithm or missing kid');
    if (!verify('sha256', Buffer.from(`${h}.${p}`), await key(header.kid), Buffer.from(sig, 'base64url'))) throw new Error('Bad signature');

    const now = Math.floor(Date.now() / 1000);
    if (claims.iss !== cfg.issuer) throw new Error('Wrong issuer');
    if (claims.aud !== cfg.clientId) throw new Error('Wrong audience');
    if (typeof claims.scp !== 'string' || !claims.scp.split(' ').includes(MCP_SCOPE_NAME)) throw new Error('Missing scope');
    if (typeof claims.exp !== 'number' || claims.exp + SKEW_S <= now) throw new Error('Token expired');
    if (claims.nbf !== undefined && (typeof claims.nbf !== 'number' || claims.nbf - SKEW_S > now)) throw new Error('Token not yet valid');
    // Older tokens must be refreshed, which re-reads roles and fails for disabled users (same 15 minutes as web sessions).
    if (typeof claims.iat !== 'number' || claims.iat < now - MAX_TOKEN_AGE_S || claims.iat - SKEW_S > now) throw new Error('Token too old or issued in the future');
    return claims;
  };
}

/** Fixed window per key. `hit` returns 0 when allowed, else the seconds until the window resets. `cost` 0 only checks. */
export function createRateLimiter(limit: number, windowMs: number) {
  const windows = new Map<string | number, { start: number; count: number }>();
  return function hit(key: string | number, cost = 1) {
    const now = Date.now();
    if (windows.size > 10_000) for (const [k, w] of windows) if (now - w.start >= windowMs) windows.delete(k);
    let w = windows.get(key);
    if (!w || now - w.start >= windowMs) {
      if (!cost) return 0;
      w = { start: now, count: 0 };
      windows.set(key, w);
    }
    w.count += cost;
    return w.count > limit ? Math.max(1, Math.ceil((w.start + windowMs - now) / 1000)) : 0;
  };
}
