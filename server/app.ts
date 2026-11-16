import type { IncomingMessage, ServerResponse } from 'node:http';
import type { DatabaseSync } from 'node:sqlite';
import { randomBytes } from 'node:crypto';
import * as client from 'openid-client';
import { checkPassword, hashPassword } from './db.ts';

type User = { id: number; name: string; admin: number };
export type OidcConfig = { issuer: string; clientId: string; clientSecret: string; redirectUri: string };
type Body = Record<string, unknown>;

class HttpError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function readJson(req: IncomingMessage): Promise<Body> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 100_000) throw new HttpError(413, 'Request too large');
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  let body: unknown;
  try {
    body = JSON.parse(Buffer.concat(chunks).toString());
  } catch {
    throw new HttpError(400, 'Invalid JSON');
  }
  if (typeof body !== 'object' || body === null || Array.isArray(body)) throw new HttpError(400, 'Expected a JSON object');
  return body as Body;
}

function text(v: unknown, field: string, min = 1, max = 50) {
  if (typeof v !== 'string' || v.trim().length < min || v.trim().length > max)
    throw new HttpError(400, `${field} must be ${min}-${max} characters`);
  return v.trim();
}

/** Normalizes to UTC ISO strings so SQLite string comparison orders times correctly. */
function time(v: unknown, field: string) {
  const d = typeof v === 'string' ? new Date(v) : null;
  if (!d || isNaN(d.getTime())) throw new HttpError(400, `${field} must be a valid date/time`);
  return d.toISOString();
}

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

export function createHandler(db: DatabaseSync, oidc?: OidcConfig) {
  const q = {
    userByName: db.prepare('SELECT id, name, admin, pass FROM users WHERE name = ?'),
    userByOid: db.prepare('SELECT id FROM users WHERE oid = ?'),
    userByToken: db.prepare('SELECT u.id, u.name, u.admin, s.expires_at AS expiresAt FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?'),
    addUser: db.prepare('INSERT INTO users (name, pass) VALUES (?, ?)'),
    addOidcUser: db.prepare("INSERT INTO users (name, pass, admin, oid) VALUES (?, '', ?, ?)"),
    updateOidcUser: db.prepare('UPDATE users SET name = ?, admin = ? WHERE id = ?'),
    addSession: db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)'),
    delSession: db.prepare('DELETE FROM sessions WHERE token = ?'),
    rooms: db.prepare('SELECT id, name FROM rooms ORDER BY name'),
    room: db.prepare('SELECT id FROM rooms WHERE id = ?'),
    addRoom: db.prepare('INSERT INTO rooms (name) VALUES (?)'),
    renameRoom: db.prepare('UPDATE rooms SET name = ? WHERE id = ?'),
    delRoom: db.prepare('DELETE FROM rooms WHERE id = ?'),
    bookings: db.prepare(`
      SELECT b.id, b.room_id AS roomId, b.user_id AS userId, u.name AS userName, b.start_at AS start, b.end_at AS end
      FROM bookings b JOIN users u ON u.id = b.user_id
      WHERE b.start_at < ? AND b.end_at > ? ORDER BY b.start_at`),
    clash: db.prepare('SELECT 1 FROM bookings WHERE room_id = ? AND start_at < ? AND end_at > ?'),
    addBooking: db.prepare('INSERT INTO bookings (room_id, user_id, start_at, end_at) VALUES (?, ?, ?, ?)'),
    booking: db.prepare('SELECT user_id AS userId FROM bookings WHERE id = ?'),
    delBooking: db.prepare('DELETE FROM bookings WHERE id = ?'),
  };

  // expiresAt null: password sessions keep no server expiry until password login is removed (job 003).
  function startSession(user: { id: number; name: string; admin: number }, expiresAt: number | null = null) {
    const token = randomBytes(32).toString('base64url');
    q.addSession.run(token, user.id, expiresAt);
    return { token, user: { id: user.id, name: user.name, admin: !!user.admin } };
  }

  // Secure always: localhost counts as a secure context, and deployed HTTPS ends at a proxy in front of plain-HTTP Node.
  const sessionCookie = (value: string, maxAge: number) => `session=${value}; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=${maxAge}`;
  const oidcCookie = (value: string, maxAge: number) => `oidc=${value}; Path=/api/callback; HttpOnly; SameSite=Lax; Secure; Max-Age=${maxAge}`;

  let discovered: Promise<client.Configuration> | undefined;
  const oidcClient = () => {
    if (!oidc) throw new Error('OIDC is not configured (OIDC_* env vars missing)');
    const { hostname, protocol } = new URL(oidc.issuer);
    // Plain http only for a local mock provider; Entra is always https.
    const insecure = protocol === 'http:' && (hostname === 'localhost' || hostname === '127.0.0.1');
    discovered ??= client.discovery(new URL(oidc.issuer), oidc.clientId, oidc.clientSecret, undefined, {
      execute: [...(insecure ? [client.allowInsecureRequests] : []), client.enableNonRepudiationChecks],
    }).catch((e) => { discovered = undefined; throw e; });
    return discovered;
  };

  async function signIn(url: URL, flow: string) {
    const [verifier, state, nonce] = flow.split('.');
    if (!verifier || !state || !nonce) throw new Error('OIDC flow cookie missing or expired');
    const config = await oidcClient();
    const currentUrl = new URL(url.pathname + url.search, oidc!.redirectUri);
    const tokens = await client.authorizationCodeGrant(config, currentUrl, { pkceCodeVerifier: verifier, expectedState: state, expectedNonce: nonce, idTokenExpected: true });
    const claims = tokens.claims()!;
    if (typeof claims.oid !== 'string' || !claims.oid) throw new Error('ID token has no oid claim');
    const oid = claims.oid;
    const claimed = typeof claims.name === 'string' && claims.name.trim() ? claims.name : claims.preferred_username;
    let name = typeof claimed === 'string' ? claimed.trim().slice(0, 50) : '';
    if (!name) throw new Error('ID token has no name or preferred_username claim');
    const admin = Array.isArray(claims.roles) && claims.roles.includes('Admin') ? 1 : 0;
    const existing = q.userByOid.get(oid) as { id: number } | undefined;
    const taken = q.userByName.get(name) as { id: number } | undefined;
    if (taken && taken.id !== existing?.id) name = `${name} (${oid.slice(0, 8)})`;
    let id = existing?.id;
    if (id) q.updateOidcUser.run(name, admin, id);
    else id = Number(q.addOidcUser.run(name, admin, oid).lastInsertRowid);
    return startSession({ id, name, admin }, Date.now() + OIDC_SESSION_MS);
  }

  async function route(req: IncomingMessage, res: ServerResponse, method: string, path: string, url: URL): Promise<unknown> {
    const body = method === 'POST' || method === 'PATCH' ? await readJson(req) : {};

    if (method === 'GET' && path === '/api/login') {
      try {
        const config = await oidcClient();
        const verifier = client.randomPKCECodeVerifier();
        const state = client.randomState();
        const nonce = client.randomNonce();
        const silent = url.searchParams.get('silent') === '1';
        const target = client.buildAuthorizationUrl(config, {
          redirect_uri: oidc!.redirectUri,
          scope: 'openid profile email',
          code_challenge: await client.calculatePKCECodeChallenge(verifier),
          code_challenge_method: 'S256',
          state,
          nonce,
          ...(silent && { prompt: 'none' }),
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

    if (method === 'POST' && path === '/api/login') {
      // Cross-site forms cannot send application/json, so this blocks login CSRF.
      if (!/^application\/json\s*(;|$)/i.test(req.headers['content-type'] ?? '')) throw new HttpError(415, 'Expected application/json');
      const row = q.userByName.get(String(body.name ?? '')) as (User & { pass: string }) | undefined;
      if (!row || !checkPassword(String(body.password ?? ''), row.pass)) throw new HttpError(401, 'Wrong name or password');
      const { token, user } = startSession(row);
      res.setHeader('Set-Cookie', sessionCookie(token, 60 * 60 * 24 * 30));
      return { user };
    }

    const token = cookie(req, 'session');
    const user = q.userByToken.get(token) as (User & { expiresAt: number | null }) | undefined;
    if (user && user.expiresAt !== null && user.expiresAt <= Date.now()) {
      // Deleting the row first means a failed silent re-sign-in ends in a plain 401, so the client cannot loop.
      q.delSession.run(token);
      res.setHeader('Set-Cookie', sessionCookie('', 0));
      res.writeHead(401, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: 'Session expired', reauth: true }));
      return;
    }
    if (!user) throw new HttpError(401, 'Not logged in');
    const requireAdmin = () => { if (!user.admin) throw new HttpError(403, 'Admins only'); };

    if (method === 'GET' && path === '/api/me') return { id: user.id, name: user.name, admin: !!user.admin };
    if (method === 'POST' && path === '/api/logout') {
      q.delSession.run(token);
      res.setHeader('Set-Cookie', sessionCookie('', 0));
      return {};
    }

    if (method === 'POST' && path === '/api/users') {
      requireAdmin();
      const name = text(body.name, 'Name');
      const password = text(body.password, 'Password', 4, 200);
      return { id: Number(q.addUser.run(name, hashPassword(password)).lastInsertRowid) };
    }

    if (path === '/api/rooms') {
      if (method === 'GET') return q.rooms.all();
      if (method === 'POST') {
        requireAdmin();
        return { id: Number(q.addRoom.run(text(body.name, 'Room name')).lastInsertRowid) };
      }
    }
    const roomId = Number(path.match(/^\/api\/rooms\/(\d+)$/)?.[1]);
    if (roomId) {
      requireAdmin();
      const r = method === 'PATCH' ? q.renameRoom.run(text(body.name, 'Room name'), roomId)
        : method === 'DELETE' ? q.delRoom.run(roomId) : null;
      if (r) {
        if (!r.changes) throw new HttpError(404, 'Room not found');
        return {};
      }
    }

    if (path === '/api/bookings') {
      if (method === 'GET') {
        const from = time(url.searchParams.get('from'), 'from');
        const to = time(url.searchParams.get('to'), 'to');
        return q.bookings.all(to, from);
      }
      if (method === 'POST') {
        const rid = Number(body.roomId);
        const start = time(body.start, 'Start');
        const end = time(body.end, 'End');
        if (end <= start) throw new HttpError(400, 'End must be after start');
        if (!Number.isInteger(rid) || !q.room.get(rid)) throw new HttpError(404, 'Room not found');
        // Check and insert run synchronously with no await between, so no other request can interleave.
        if (q.clash.get(rid, end, start)) throw new HttpError(409, 'That room is already booked in this time');
        return { id: Number(q.addBooking.run(rid, user.id, start, end).lastInsertRowid) };
      }
    }
    const bookingId = Number(path.match(/^\/api\/bookings\/(\d+)$/)?.[1]);
    if (bookingId && method === 'DELETE') {
      const b = q.booking.get(bookingId) as { userId: number } | undefined;
      if (!b) throw new HttpError(404, 'Booking not found');
      if (b.userId !== user.id && !user.admin) throw new HttpError(403, 'You can only cancel your own bookings');
      q.delBooking.run(bookingId);
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
