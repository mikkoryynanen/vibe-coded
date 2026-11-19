import type { IncomingMessage, ServerResponse } from 'node:http';
import type { DatabaseSync } from 'node:sqlite';
import { randomBytes } from 'node:crypto';
import * as client from 'openid-client';
import { createMcp } from './mcp.ts';
import { createService, HttpError, readJson, requireAdmin } from './service.ts';

type User = { id: number; name: string; admin: number };
export type OidcConfig = { issuer: string; clientId: string; clientSecret: string; redirectUri: string };

const cookie = (req: IncomingMessage, name: 'session' | 'oidc') =>
  req.headers.cookie?.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`))?.[1] ?? '';

const redirect = (res: ServerResponse, location: string) => { res.writeHead(302, { Location: location }).end(); };

// Server log only: openid-client keeps the specific reason (bad state, signature, aud...) in `cause`.
const logOidcFailure = (step: string, e: unknown) => {
  const cause = e instanceof Error ? e.cause : undefined;
  console.error(`OIDC ${step} failed:`, e instanceof Error ? e.message : e, cause instanceof Error ? `(${cause.message})` : '');
};

// OIDC sessions end after this, so the next silent sign-in re-reads the Entra roles.
const OIDC_SESSION_MS = 15 * 60 * 1000;

/** Reads the four required OIDC_* vars; throws naming the missing ones (never their values). */
export function oidcConfigFromEnv(env: Record<string, string | undefined>): OidcConfig {
  const missing = ['OIDC_ISSUER', 'OIDC_CLIENT_ID', 'OIDC_CLIENT_SECRET', 'OIDC_REDIRECT_URI'].filter((k) => !env[k]?.trim());
  if (missing.length) throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  return { issuer: env.OIDC_ISSUER!, clientId: env.OIDC_CLIENT_ID!, clientSecret: env.OIDC_CLIENT_SECRET!, redirectUri: env.OIDC_REDIRECT_URI! };
}

export function createHandler(db: DatabaseSync, oidc: OidcConfig, opts: { mcpScope?: string } = {}) {
  const service = createService(db);
  const q = {
    userByToken: db.prepare('SELECT u.id, u.name, u.admin, s.expires_at AS expiresAt FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?'),
    addSession: db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)'),
    delSession: db.prepare('DELETE FROM sessions WHERE token = ?'),
  };

  function startSession(user: { id: number; name: string; admin: boolean }, expiresAt: number) {
    const token = randomBytes(32).toString('base64url');
    q.addSession.run(token, user.id, expiresAt);
    return { token, user: { id: user.id, name: user.name, admin: !!user.admin } };
  }

  // Secure always: localhost counts as a secure context, and deployed HTTPS ends at a proxy in front of plain-HTTP Node.
  const sessionCookie = (value: string, maxAge: number) => `session=${value}; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=${maxAge}`;
  const oidcCookie = (value: string, maxAge: number) => `oidc=${value}; Path=/api/callback; HttpOnly; SameSite=Lax; Secure; Max-Age=${maxAge}`;

  let discovered: Promise<client.Configuration> | undefined;
  const oidcClient = () => {
    const { hostname, protocol } = new URL(oidc.issuer);
    // Plain http only for a local mock provider; Entra is always https.
    const insecure = protocol === 'http:' && (hostname === 'localhost' || hostname === '127.0.0.1');
    discovered ??= client.discovery(new URL(oidc.issuer), oidc.clientId, oidc.clientSecret, undefined, {
      execute: [...(insecure ? [client.allowInsecureRequests] : []), client.enableNonRepudiationChecks],
    }).catch((e) => { discovered = undefined; throw e; });
    return discovered;
  };

  const mcp = createMcp(service, { ...oidc, scope: opts.mcpScope, jwksUri: async () => (await oidcClient()).serverMetadata().jwks_uri });

  async function signIn(url: URL, flow: string) {
    const [verifier, state, nonce] = flow.split('.');
    if (!verifier || !state || !nonce) throw new Error('OIDC flow cookie missing or expired');
    const config = await oidcClient();
    const currentUrl = new URL(url.pathname + url.search, oidc.redirectUri);
    const tokens = await client.authorizationCodeGrant(config, currentUrl, { pkceCodeVerifier: verifier, expectedState: state, expectedNonce: nonce, idTokenExpected: true });
    const user = service.upsertOidcUser(tokens.claims()!);
    return startSession(user, Date.now() + OIDC_SESSION_MS);
  }

  async function route(req: IncomingMessage, res: ServerResponse, method: string, path: string, url: URL): Promise<unknown> {
    // MCP uses bearer tokens only (never the session cookie) and authenticates before reading the body.
    if (path === '/mcp') return mcp.handle(req, res, method);
    if (method === 'GET' && path === '/.well-known/oauth-protected-resource') return mcp.metadata();

    const body = method === 'POST' || method === 'PATCH' ? await readJson(req) : {};

    if (method === 'GET' && path === '/api/login') {
      try {
        const config = await oidcClient();
        const verifier = client.randomPKCECodeVerifier();
        const state = client.randomState();
        const nonce = client.randomNonce();
        const silent = url.searchParams.get('silent') === '1';
        const target = client.buildAuthorizationUrl(config, {
          redirect_uri: oidc.redirectUri,
          scope: 'openid profile email',
          code_challenge: await client.calculatePKCECodeChallenge(verifier),
          code_challenge_method: 'S256',
          state,
          nonce,
          // Interactive: let the user pick the account even when the browser already has a Microsoft session.
          prompt: silent ? 'none' : 'select_account',
        });
        res.setHeader('Set-Cookie', oidcCookie([verifier, state, nonce, silent ? 1 : 0].join('.'), 600));
        return redirect(res, target.href);
      } catch (e) {
        logOidcFailure('login', e);
        return redirect(res, '/?login_error=1');
      }
    }

    if (method === 'GET' && path === '/api/callback') {
      const flow = cookie(req, 'oidc');
      try {
        const { token } = await signIn(url, flow);
        res.setHeader('Set-Cookie', [oidcCookie('', 0), sessionCookie(token, 60 * 60 * 24 * 30)]);
        return redirect(res, '/');
      } catch (e) {
        logOidcFailure('callback', e);
        res.setHeader('Set-Cookie', oidcCookie('', 0));
        // A failed silent re-check (login_required etc.) shows the plain login screen, not an error.
        const silent = flow.split('.')[3] === '1';
        return redirect(res, silent && url.searchParams.has('error') ? '/' : '/?login_error=1');
      }
    }

    const token = cookie(req, 'session');
    const user = q.userByToken.get(token) as (User & { expiresAt: number | null }) | undefined;
    if (!user) throw new HttpError(401, 'Not logged in');
    // Before the expiry check: logging out of an expired session must not answer reauth, or the client signs straight back in.
    if (method === 'POST' && path === '/api/logout') {
      q.delSession.run(token);
      res.setHeader('Set-Cookie', sessionCookie('', 0));
      return {};
    }
    // NULL expiry is a leftover password session from before Microsoft sign-in only; treat it as expired.
    if (user.expiresAt === null || user.expiresAt <= Date.now()) {
      // Deleting the row first means a failed silent re-sign-in ends in a plain 401, so the client cannot loop.
      q.delSession.run(token);
      res.setHeader('Set-Cookie', sessionCookie('', 0));
      res.writeHead(401, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: 'Session expired', reauth: true }));
      return;
    }
    const acting = { id: user.id, name: user.name, admin: !!user.admin };

    if (method === 'GET' && path === '/api/me') return acting;

    if (path === '/api/rooms') {
      if (method === 'GET') return service.listRooms();
      if (method === 'POST') return service.addRoom(acting, body.name);
    }
    const roomId = Number(path.match(/^\/api\/rooms\/(\d+)$/)?.[1]);
    if (roomId) {
      requireAdmin(acting);
      if (method === 'PATCH') {
        service.renameRoom(acting, roomId, body.name);
        return {};
      }
      if (method === 'DELETE') {
        service.deleteRoom(acting, roomId);
        return {};
      }
    }

    if (path === '/api/bookings') {
      if (method === 'GET') return service.listBookings(url.searchParams.get('from'), url.searchParams.get('to'));
      if (method === 'POST') return service.bookRoom(acting, body.roomId, body.start, body.end);
    }
    const bookingId = Number(path.match(/^\/api\/bookings\/(\d+)$/)?.[1]);
    if (bookingId && method === 'DELETE') {
      service.cancelBooking(acting, bookingId);
      return {};
    }

    throw new HttpError(404, 'Not found');
  }

  return async (req: IncomingMessage, res: ServerResponse) => {
    let status = 200;
    let result: unknown;
    try {
      const url = new URL(req.url ?? '/', 'http://localhost');
      result = await route(req, res, req.method ?? 'GET', url.pathname, url);
    } catch (e) {
      if (e instanceof HttpError) [status, result] = [e.status, { error: e.message }];
      else if (e instanceof Error && e.message.includes('UNIQUE')) [status, result] = [409, { error: 'That name is already taken' }];
      else {
        console.error(e);
        [status, result] = [500, { error: 'Server error' }];
      }
    }
    // Redirects and the session-expired 401 are written inside route().
    if (!res.writableEnded) res.writeHead(status, { 'Content-Type': 'application/json' }).end(JSON.stringify(result));
  };
}
