import type { IncomingMessage, ServerResponse } from 'node:http';
import { createRateLimiter, httpsOrLocal } from './bearer.ts';
import { HttpError, readBody } from './service.ts';

type OAuthProxyConfig = {
  clientId: string;
  origin: string;
  scope: string;
  endpoints: () => Promise<{ authorize?: string; token?: string }>;
};

const AUTHORIZE_PARAMS = ['response_type', 'client_id', 'redirect_uri', 'scope', 'state', 'code_challenge', 'code_challenge_method'];
const TOKEN_PARAMS = ['grant_type', 'client_id', 'code', 'redirect_uri', 'code_verifier', 'refresh_token', 'scope'];
const MAX_PARAM = 8192;

class OAuthError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

const send = (res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) => {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...headers }).end(JSON.stringify(body));
};

/** Reads the allowed parameters; anything else (such as RFC 8707 `resource`, which Entra v2 rejects) is dropped. */
function pick(params: URLSearchParams, names: string[]) {
  const out = new URLSearchParams();
  for (const name of names) {
    const values = params.getAll(name);
    if (values.length > 1) throw new OAuthError(400, 'invalid_request', `Repeated parameter: ${name}`);
    if (values[0] === undefined || values[0] === '') continue;
    if (values[0].length > MAX_PARAM) throw new OAuthError(400, 'invalid_request', `Parameter too long: ${name}`);
    out.set(name, values[0]);
  }
  return out;
}

function requireParam(params: URLSearchParams, name: string, valid: (v: string) => boolean = () => true) {
  const v = params.get(name);
  if (v === null) throw new OAuthError(400, 'invalid_request', `Missing ${name}`);
  if (!valid(v)) throw new OAuthError(400, 'invalid_request', `Invalid ${name}`);
}

/** RFC 8252 loopback redirect for native clients such as Claude Code. */
const loopback = (v: string) => {
  try {
    const u = new URL(v);
    return u.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname) && !u.username && !u.password && !u.hash;
  } catch {
    return false;
  }
};

/**
 * Stateless OAuth proxy in front of Entra: MCP clients send RFC 8707 `resource`, which Entra v2 rejects (AADSTS9010010).
 * Only public-client PKCE flows pass; no client secret is ever added and tokens are never logged.
 */
export function createOAuthProxy(cfg: OAuthProxyConfig) {
  const tokenLimit = createRateLimiter(30, 60_000);

  const metadata = () => ({
    issuer: cfg.origin,
    authorization_endpoint: `${cfg.origin}/oauth/authorize`,
    token_endpoint: `${cfg.origin}/oauth/token`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none'],
    scopes_supported: [cfg.scope, 'offline_access'],
  });

  async function upstream(name: 'authorize' | 'token') {
    const uri = (await cfg.endpoints())[name];
    if (!uri || !httpsOrLocal(uri)) throw new Error(`Issuer metadata has no usable ${name} endpoint`);
    return new URL(uri);
  }

  async function authorize(res: ServerResponse, url: URL) {
    try {
      const params = pick(url.searchParams, AUTHORIZE_PARAMS);
      if (params.get('client_id') !== cfg.clientId) throw new OAuthError(400, 'invalid_client', 'Unknown client_id');
      requireParam(params, 'redirect_uri', loopback);
      requireParam(params, 'response_type', (v) => v === 'code');
      requireParam(params, 'code_challenge', (v) => /^[A-Za-z0-9_-]{43}$/.test(v));
      requireParam(params, 'code_challenge_method', (v) => v === 'S256');
      // Entra returns a refresh token only for offline_access; tokens older than 15 minutes are refused at /mcp.
      const scopes = (params.get('scope') ?? cfg.scope).split(' ').filter(Boolean);
      params.set('scope', [...scopes, ...(scopes.includes('offline_access') ? [] : ['offline_access'])].join(' '));
      const target = await upstream('authorize');
      for (const [k, v] of params) target.searchParams.set(k, v);
      res.writeHead(302, { Location: target.href, 'Cache-Control': 'no-store' }).end();
    } catch (e) {
      if (!(e instanceof OAuthError)) throw e;
      send(res, e.status, { error: e.code, error_description: e.message });
    }
  }

  async function token(req: IncomingMessage, res: ServerResponse) {
    const retry = tokenLimit(req.socket.remoteAddress ?? '');
    if (retry) return send(res, 429, { error: 'slow_down', error_description: 'Too many requests' }, { 'Retry-After': String(retry) });
    try {
      if (!/^application\/x-www-form-urlencoded\s*(;|$)/i.test(req.headers['content-type'] ?? ''))
        throw new OAuthError(400, 'invalid_request', 'Expected application/x-www-form-urlencoded');
      let raw: string;
      try {
        raw = await readBody(req);
      } catch (e) {
        if (e instanceof HttpError && e.status === 413) throw new OAuthError(413, 'invalid_request', 'Request too large');
        throw e;
      }
      const params = pick(new URLSearchParams(raw), TOKEN_PARAMS);
      const grant = params.get('grant_type');
      if (grant === null) throw new OAuthError(400, 'invalid_request', 'Missing grant_type');
      if (grant !== 'authorization_code' && grant !== 'refresh_token') throw new OAuthError(400, 'unsupported_grant_type', 'Unsupported grant_type');
      if (params.get('client_id') !== cfg.clientId) throw new OAuthError(401, 'invalid_client', 'Unknown client_id');
      if (grant === 'authorization_code') {
        requireParam(params, 'code');
        requireParam(params, 'redirect_uri', loopback);
        requireParam(params, 'code_verifier', (v) => /^[A-Za-z0-9._~-]{43,128}$/.test(v));
        params.delete('refresh_token');
      } else {
        requireParam(params, 'refresh_token');
        for (const name of ['code', 'redirect_uri', 'code_verifier']) params.delete(name);
      }
      const endpoint = await upstream('token');
      let reply: Response;
      try {
        reply = await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
          body: params,
          redirect: 'error',
          signal: AbortSignal.timeout(10_000),
        });
      } catch (e) {
        console.error('OAuth token relay failed:', e instanceof Error ? e.name : 'unknown error');
        throw new OAuthError(502, 'temporarily_unavailable', 'Token endpoint unavailable');
      }
      const body = await reply.text();
      if (!reply.headers.get('content-type')?.includes('json')) {
        console.error('OAuth token relay failed: non-JSON reply with status', reply.status);
        throw new OAuthError(502, 'temporarily_unavailable', 'Token endpoint unavailable');
      }
      res.writeHead(reply.status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', Pragma: 'no-cache' }).end(body);
    } catch (e) {
      if (!(e instanceof OAuthError)) throw e;
      send(res, e.status, { error: e.code, error_description: e.message });
    }
  }

  return { metadata, authorize, token };
}
