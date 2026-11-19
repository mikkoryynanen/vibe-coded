import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { OAuth2Issuer, OAuth2Server } from 'oauth2-mock-server';
import { openDb } from './db.ts';
import { createHandler, oidcConfigFromEnv } from './app.ts';

const usersCount = (db: DatabaseSync) => Number(db.prepare('SELECT COUNT(*) AS n FROM users').get()?.n);
const setCookie = (res: Response, name: string) => res.headers.getSetCookie().find((c) => c.startsWith(`${name}=`));
const cookieValue = (res: Response, name: string) => setCookie(res, name)?.match(/^[^=]+=([^;]*)/)?.[1] ?? '';

type Tamper = (cb: URL, flow: string) => string | null | Promise<string | null>;

async function startOidc(t: TestContext, opts: { mcpScope?: string } = {}) {
  const mock = new OAuth2Server();
  await mock.issuer.keys.generate('RS256');
  await mock.start(0, 'localhost');
  t.after(() => mock.stop());
  let claims: Record<string, unknown> = {};
  mock.service.on('beforeTokenSigning', (token) => Object.assign(token.payload, claims));

  const db = openDb(':memory:');
  const server = createServer().listen(0);
  t.after(() => server.close());
  const origin = `http://localhost:${(server.address() as AddressInfo).port}`;
  server.on('request', createHandler(db, { issuer: mock.issuer.url!, clientId: 'test-client', clientSecret: 'test-secret', redirectUri: `${origin}/api/callback` }, opts));
  const base = `${origin}/api`;

  /** Runs login -> mock authorize -> callback. `tamper` may change the callback URL and returns the flow cookie to send. */
  async function signIn(next: Record<string, unknown>, opts: { silent?: boolean; tamper?: Tamper } = {}) {
    claims = next;
    const login = await fetch(`${base}/login${opts.silent ? '?silent=1' : ''}`, { redirect: 'manual' });
    assert.equal(login.status, 302);
    const flow = cookieValue(login, 'oidc');
    const authorizeUrl = new URL(login.headers.get('location')!);
    const authz = await fetch(authorizeUrl, { redirect: 'manual' });
    const cb = new URL(authz.headers.get('location')!);
    const sent = opts.tamper ? await opts.tamper(cb, flow) : flow;
    const res = await fetch(cb, { redirect: 'manual', headers: sent === null ? {} : { Cookie: `oidc=${sent}` } });
    return { res, token: cookieValue(res, 'session'), location: res.headers.get('location'), authorizeUrl };
  }
  const call = async (method: string, path: string, token?: string, body?: object) => {
    const res = await fetch(base + path, { method, headers: { 'Content-Type': 'application/json', ...(token && { Cookie: `session=${token}` }) }, body: body && JSON.stringify(body) });
    return { status: res.status, data: await res.json(), res };
  };
  return { mock, db, origin, base, signIn, call };
}

/** A session row inserted directly, as Microsoft sign-in would leave it. */
function addSession(db: DatabaseSync, name: string, expiresAt: number | null = Date.now() + 60_000) {
  const userId = Number(db.prepare('INSERT INTO users (name, admin, oid) VALUES (?, 0, ?)').run(name, `oid-${name}`).lastInsertRowid);
  const token = `tok-${name}`;
  db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)').run(token, userId, expiresAt);
  return token;
}

test('booking flow', async (t) => {
  const { signIn, call } = await startOidc(t);
  assert.equal((await call('GET', '/rooms')).status, 401);
  assert.equal((await call('POST', '/register', undefined, { name: 'eve', password: 'password' })).status, 401, 'no self-registration');

  const admin = (await signIn({ oid: 'oid-admin', name: 'admin', roles: ['Admin'] })).token;
  const alice = (await signIn({ oid: 'oid-alice', name: 'alice' })).token;
  const bob = (await signIn({ oid: 'oid-bob', name: 'bob' })).token;

  assert.equal((await call('POST', '/rooms', alice, { name: 'Desk 1' })).status, 403);
  const roomId = (await call('POST', '/rooms', admin, { name: 'Desk 1' })).data.id;
  assert.equal((await call('POST', '/rooms', admin, { name: 'desk 1' })).status, 409);

  const book = (token: string, start: string, end: string) =>
    call('POST', '/bookings', token, { roomId, start: `2030-01-01T${start}Z`, end: `2030-01-01T${end}Z` });

  const first = await book(alice, '09:00', '10:00');
  assert.equal(first.status, 200);
  assert.equal((await book(bob, '09:30', '10:30')).status, 409, 'overlap rejected');
  assert.equal((await book(bob, '08:00', '11:00')).status, 409, 'enclosing rejected');
  assert.equal((await book(bob, '10:00', '11:00')).status, 200, 'back-to-back allowed');
  assert.equal((await book(bob, '12:00', '11:00')).status, 400);
  assert.equal((await call('POST', '/bookings', bob, { roomId: 999, start: '2030-01-01T12:00Z', end: '2030-01-01T13:00Z' })).status, 404);

  const day = await call('GET', '/bookings?from=2030-01-01T00:00Z&to=2030-01-02T00:00Z', bob);
  assert.deepEqual(day.data.map((b: { userName: string }) => b.userName), ['alice', 'bob']);

  assert.equal((await call('DELETE', `/bookings/${first.data.id}`, bob)).status, 403);
  assert.equal((await call('DELETE', `/bookings/${first.data.id}`, admin)).status, 200);

  assert.equal((await call('DELETE', `/rooms/${roomId}`, admin)).status, 200);
  const after = await call('GET', '/bookings?from=2030-01-01T00:00Z&to=2030-01-02T00:00Z', bob);
  assert.equal(after.data.length, 0, 'deleting a room removes its bookings');
});

test('session cookie', async (t) => {
  const { db, base, call } = await startOidc(t);
  const token = addSession(db, 'carol');
  const me = (headers: Record<string, string>) => fetch(base + '/me', { headers });

  const ok = await me({ Cookie: `other=1; session=${token}` });
  assert.equal(ok.status, 200);
  assert.equal((await ok.json()).name, 'carol');
  for (const headers of [{}, { Cookie: 'session=bogus' }, { Cookie: 'session=' }, { Authorization: `Bearer ${token}` }] as Record<string, string>[]) {
    const r = await me(headers);
    assert.equal(r.status, 401, JSON.stringify(headers));
    assert.equal((await r.json()).error, 'Not logged in');
  }

  const out = await call('POST', '/logout', token);
  assert.equal(out.status, 200);
  const cleared = out.res.headers.get('set-cookie') ?? '';
  assert.ok(cleared.startsWith('session=;'), cleared);
  assert.ok(cleared.includes('Max-Age=0') && cleared.includes('Secure'), cleared);
  assert.equal((await call('GET', '/me', token)).status, 401);

  const again = await call('POST', '/logout', token);
  assert.equal(again.status, 401, 'logout without a valid session stays 401');
  assert.equal(again.res.headers.get('set-cookie'), null);
});

test('password login and user creation are gone', async (t) => {
  const { db, signIn, call } = await startOidc(t);
  // An old password user (its hash went with the dropped pass column) cannot sign in any more.
  db.prepare("INSERT INTO users (name, admin) VALUES ('admin', 1)").run();
  const users = usersCount(db);
  const sessions = () => Number(db.prepare('SELECT COUNT(*) AS n FROM sessions').get()?.n);

  const pw = await call('POST', '/login', undefined, { name: 'admin', password: 'admin-pass' });
  assert.equal(pw.status, 401);
  assert.equal(setCookie(pw.res, 'session'), undefined);
  assert.equal(sessions(), 0);
  assert.equal((await call('POST', '/users', undefined, { name: 'eve', password: 'password' })).status, 401);

  const admin = (await signIn({ oid: 'oid-root', name: 'Root', roles: ['Admin'] })).token;
  const user = (await signIn({ oid: 'oid-user', name: 'User' })).token;
  assert.equal((await call('POST', '/login', admin, { name: 'admin', password: 'admin-pass' })).status, 404);
  assert.equal((await call('POST', '/users', admin, { name: 'eve', password: 'password' })).status, 404);
  assert.equal((await call('POST', '/users', user, { name: 'eve', password: 'password' })).status, 404);
  assert.equal(usersCount(db), users + 2, 'only the two Microsoft sign-ins added users');
  assert.equal(db.prepare("SELECT 1 FROM users WHERE name = 'eve'").get(), undefined);
});

test('a session without expiry (old password session) asks for reauth', async (t) => {
  const { db, call } = await startOidc(t);
  const token = addSession(db, 'legacy', null);
  const res = await call('GET', '/me', token);
  assert.equal(res.status, 401);
  assert.deepEqual(res.data, { error: 'Session expired', reauth: true });
  assert.equal(db.prepare('SELECT 1 FROM sessions WHERE token = ?').get(token), undefined, 'row deleted');
});

test('oidcConfigFromEnv requires all four OIDC vars', () => {
  const env = { OIDC_ISSUER: 'https://issuer', OIDC_CLIENT_ID: 'id', OIDC_CLIENT_SECRET: 'top-secret-value', OIDC_REDIRECT_URI: 'http://localhost/api/callback' };
  assert.deepEqual(oidcConfigFromEnv(env), { issuer: 'https://issuer', clientId: 'id', clientSecret: 'top-secret-value', redirectUri: 'http://localhost/api/callback' });
  assert.throws(() => oidcConfigFromEnv({}), /OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_REDIRECT_URI/);
  for (const key of Object.keys(env)) {
    for (const value of [undefined, '', '  ']) {
      assert.throws(() => oidcConfigFromEnv({ ...env, [key]: value }), (e: Error) => {
        assert.ok(e.message.includes(key), e.message);
        assert.ok(!e.message.includes('top-secret-value'), 'secret value never in the message');
        assert.equal(e.message.split(',').length, 1, 'only the missing var is named');
        return true;
      });
    }
  }
});

test('oidc login redirect and flow cookie', async (t) => {
  const { base, signIn } = await startOidc(t);
  const login = await fetch(`${base}/login`, { redirect: 'manual' });
  assert.equal(login.status, 302);
  const to = new URL(login.headers.get('location')!);
  assert.equal(to.pathname, '/authorize');
  for (const [k, v] of [['response_type', 'code'], ['scope', 'openid profile email'], ['code_challenge_method', 'S256'], ['client_id', 'test-client']])
    assert.equal(to.searchParams.get(k), v, k);
  for (const k of ['state', 'nonce', 'code_challenge']) assert.ok(to.searchParams.get(k), k);
  assert.match(to.searchParams.get('redirect_uri')!, /^http:\/\/localhost:\d+\/api\/callback$/);
  assert.equal(to.searchParams.get('prompt'), 'select_account', 'interactive login lets the user choose the account');
  assert.equal(to.searchParams.get('response_mode'), null, 'default query response mode');
  const flow = setCookie(login, 'oidc') ?? '';
  for (const part of ['HttpOnly', 'SameSite=Lax', 'Secure', 'Path=/api/callback', 'Max-Age=600'])
    assert.ok(flow.split('; ').includes(part), `oidc cookie has ${part}: ${flow}`);
  assert.equal(setCookie(login, 'session'), undefined);

  const silent = await signIn({ oid: 'oid-silent', name: 'Silent' }, { silent: true });
  assert.equal(silent.authorizeUrl.searchParams.get('prompt'), 'none');
  assert.equal(silent.location, '/', 'a successful silent sign-in lands signed in');
  const other = await fetch(`${base}/login?silent=yes`, { redirect: 'manual' });
  assert.equal(new URL(other.headers.get('location')!).searchParams.get('prompt'), 'select_account', 'only silent=1 counts');
});

test('oidc sign-in creates, reuses and updates the user', async (t) => {
  const { db, signIn, call } = await startOidc(t);
  const before = usersCount(db);
  const first = await signIn({ oid: 'oid-alice-1234', name: 'Alice Entra', roles: ['Admin'] });
  assert.equal(first.res.status, 302);
  assert.equal(first.location, '/');
  assert.ok(first.token);
  for (const part of ['HttpOnly', 'SameSite=Lax', 'Secure', 'Path=/'])
    assert.ok(setCookie(first.res, 'session')!.split('; ').includes(part), part);
  assert.ok(setCookie(first.res, 'oidc')!.includes('Max-Age=0'), 'flow cookie cleared');
  const me = await call('GET', '/me', first.token);
  assert.equal(me.status, 200);
  assert.deepEqual({ name: me.data.name, admin: me.data.admin }, { name: 'Alice Entra', admin: true });
  assert.equal(usersCount(db), before + 1);
  assert.deepEqual({ ...db.prepare('SELECT * FROM users WHERE oid = ?').get('oid-alice-1234') }, { id: me.data.id, name: 'Alice Entra', admin: 1, oid: 'oid-alice-1234' }, 'no pass column');

  const second = await signIn({ oid: 'oid-alice-1234', name: 'Alice Entra' });
  const me2 = await call('GET', '/me', second.token);
  assert.equal(me2.data.id, me.data.id, 'same oid reuses the user');
  assert.equal(me2.data.admin, false, 'removed Admin role revokes admin on next login');
  assert.equal(usersCount(db), before + 1);

  const pref = await signIn({ oid: 'oid-pref', preferred_username: 'pref@example.com' });
  assert.equal((await call('GET', '/me', pref.token)).data.name, 'pref@example.com');
  const long = await signIn({ oid: 'oid-long', name: `  ${'x'.repeat(80)}  ` });
  assert.equal((await call('GET', '/me', long.token)).data.name, 'x'.repeat(50));

  const twin = await signIn({ oid: 'oid-other-5678', name: 'alice entra' });
  assert.equal((await call('GET', '/me', twin.token)).data.name, 'alice entra (oid-othe)', 'same name, different oid');
  const twinAgain = await signIn({ oid: 'oid-other-5678', name: 'alice entra' });
  assert.equal((await call('GET', '/me', twinAgain.token)).data.name, 'alice entra (oid-othe)', 'stable on re-login');
  const alice = await signIn({ oid: 'oid-alice-1234', name: 'Alice Entra' });
  assert.equal((await call('GET', '/me', alice.token)).data.name, 'Alice Entra');

});

test('oidc sessions expire and ask for a silent re-sign-in', async (t) => {
  const { db, base, signIn, call } = await startOidc(t);
  const { token } = await signIn({ oid: 'oid-exp', name: 'Expiring' });
  const exp = Number(db.prepare('SELECT expires_at AS e FROM sessions WHERE token = ?').get(token)?.e);
  assert.ok(exp > Date.now() + 14 * 60_000 && exp <= Date.now() + 15 * 60_000, 'expires in 15 minutes');
  assert.equal((await call('GET', '/me', token)).status, 200);

  db.prepare('UPDATE sessions SET expires_at = ? WHERE token = ?').run(Date.now() - 1000, token);
  const expired = await call('GET', '/rooms', token);
  assert.equal(expired.status, 401);
  assert.deepEqual(expired.data, { error: 'Session expired', reauth: true });
  const cleared = setCookie(expired.res, 'session') ?? '';
  assert.ok(cleared.startsWith('session=;') && cleared.includes('Max-Age=0'), cleared);
  assert.equal(db.prepare('SELECT 1 FROM sessions WHERE token = ?').get(token), undefined, 'expired row deleted');
  const again = await call('GET', '/rooms', token);
  assert.equal(again.status, 401);
  assert.deepEqual(again.data, { error: 'Not logged in' }, 'no reauth the second time, so no loop');

  const leaving = (await signIn({ oid: 'oid-exp', name: 'Expiring' })).token;
  db.prepare('UPDATE sessions SET expires_at = ? WHERE token = ?').run(Date.now() - 1000, leaving);
  const out = await call('POST', '/logout', leaving);
  assert.equal(out.status, 200, 'logout of an expired session succeeds instead of asking for reauth');
  assert.deepEqual(out.data, {});
  assert.ok(setCookie(out.res, 'session')?.includes('Max-Age=0'), 'session cookie cleared');
  assert.equal(db.prepare('SELECT 1 FROM sessions WHERE token = ?').get(leaving), undefined, 'row deleted');
  assert.equal((await call('POST', '/logout')).status, 401, 'logout without a session cookie stays 401');
  assert.equal((await call('POST', '/logout', leaving)).status, 401);

  assert.equal((await fetch(`${base}/me`)).status, 401);
});

test('non-admin oidc user is still bound by admin and ownership checks', async (t) => {
  const { signIn, call } = await startOidc(t);
  const admin = (await signIn({ oid: 'oid-admin', name: 'Admin', roles: ['Admin'] })).token;
  const roomId = (await call('POST', '/rooms', admin, { name: 'Desk 1' })).data.id;
  const adminBooking = (await call('POST', '/bookings', admin, { roomId, start: '2030-01-01T09:00Z', end: '2030-01-01T10:00Z' })).data.id;
  const { token } = await signIn({ oid: 'oid-bob', name: 'Bob', roles: ['Reader'] });
  assert.equal((await call('GET', '/me', token)).data.admin, false);
  assert.equal((await call('POST', '/rooms', token, { name: 'Desk 2' })).status, 403);
  assert.equal((await call('DELETE', `/bookings/${adminBooking}`, token)).status, 403);
  assert.equal((await call('GET', '/me')).status, 401);
});

test('oidc failures redirect to a generic error and create nothing', async (t) => {
  const { mock, db, signIn } = await startOidc(t);
  const claims = { oid: 'oid-fail', name: 'Failing' };
  // Same kid as the real key, so only the signature check can catch it.
  const forger = new OAuth2Issuer();
  forger.url = mock.issuer.url;
  await forger.keys.generate('RS256', { kid: mock.issuer.keys.get()!.kid });
  const forgeIdToken: Tamper = async (_cb, flow) => {
    const nonce = flow.split('.')[2];
    const idToken = await forger.buildToken({ scopesOrTransform: (_h, p) => Object.assign(p, { sub: 'johndoe', aud: 'test-client', nonce, ...claims }) });
    mock.service.once('beforeResponse', (r) => { (r.body as Record<string, unknown>).id_token = idToken; });
    return flow;
  };
  const deny = (error: string) => mock.service.once('beforeAuthorizeRedirect', ({ url }) => {
    url.searchParams.delete('code');
    url.searchParams.set('error', error);
    url.searchParams.set('error_description', 'AADSTS-secret-detail');
  });

  const cases: [string, () => ReturnType<typeof signIn>][] = [
    ['wrong state', () => signIn(claims, { tamper: (cb, flow) => { cb.searchParams.set('state', 'wrong'); return flow; } })],
    ['missing flow cookie', () => signIn(claims, { tamper: () => null })],
    ['malformed flow cookie', () => signIn(claims, { tamper: () => 'x.y' })],
    ['wrong nonce', () => signIn({ ...claims, nonce: 'wrong' })],
    ['expired id token', () => signIn({ ...claims, exp: Math.floor(Date.now() / 1000) - 3600 })],
    ['wrong aud', () => signIn({ ...claims, aud: 'another-client' })],
    ['different signing key', () => signIn(claims, { tamper: forgeIdToken })],
    ['missing oid', () => signIn({ name: 'No Oid' })],
    ['access_denied', () => { deny('access_denied'); return signIn(claims); }],
    ['silent but wrong state', () => signIn(claims, { silent: true, tamper: (cb, flow) => { cb.searchParams.set('state', 'wrong'); return flow; } })],
  ];
  const users = usersCount(db);
  const sessions = () => db.prepare('SELECT COUNT(*) AS n FROM sessions').get()?.n;
  for (const [name, run] of cases) {
    const { res, location } = await run();
    assert.equal(res.status, 302, name);
    assert.equal(location, '/?login_error=1', name);
    assert.equal(await res.text(), '', `${name}: empty body`);
    assert.equal(setCookie(res, 'session'), undefined, `${name}: no session cookie`);
    assert.ok(setCookie(res, 'oidc')?.includes('Max-Age=0'), `${name}: flow cookie cleared`);
    assert.equal(usersCount(db), users, `${name}: no user row`);
    assert.equal(sessions(), 0, `${name}: no session row`);
  }

  deny('login_required');
  const silent = await signIn(claims, { silent: true });
  assert.equal(silent.location, '/', 'failed silent sign-in shows the plain login screen');
  assert.ok(setCookie(silent.res, 'oidc')?.includes('Max-Age=0'));
  assert.equal(setCookie(silent.res, 'session'), undefined);
  assert.equal(sessions(), 0);
  assert.equal(usersCount(db), users);

  const ok = await signIn(claims);
  assert.equal(ok.location, '/', 'the provider still works after the failures');
});

test('openDb upgrades an old-schema database in place', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'booking-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'old.db');
  const old = new DatabaseSync(path);
  old.exec(`
    CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL COLLATE NOCASE, pass TEXT NOT NULL, admin INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE sessions (token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users ON DELETE CASCADE);
    CREATE TABLE rooms (id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL COLLATE NOCASE);
    CREATE TABLE bookings (id INTEGER PRIMARY KEY, room_id INTEGER NOT NULL REFERENCES rooms ON DELETE CASCADE,
      user_id INTEGER NOT NULL REFERENCES users ON DELETE CASCADE, start_at TEXT NOT NULL, end_at TEXT NOT NULL);
    INSERT INTO users (name, pass, admin) VALUES ('old', 'salt:hash', 1);
    INSERT INTO rooms (name) VALUES ('Desk 1');
    INSERT INTO bookings (room_id, user_id, start_at, end_at) VALUES (1, 1, 'a', 'b');
    INSERT INTO sessions (token, user_id) VALUES ('tok', 1);`);
  old.close();

  for (let i = 0; i < 2; i++) {
    const db = openDb(path);
    const cols = (table: string) => (db.prepare('SELECT name FROM pragma_table_info(?)').all(table) as { name: string }[]).map((c) => c.name);
    assert.deepEqual(cols('users'), ['id', 'name', 'admin', 'oid'], 'pass column dropped');
    assert.ok(cols('sessions').includes('expires_at'));
    assert.equal(db.prepare("SELECT \"unique\" AS u FROM pragma_index_list('users') WHERE name = 'users_oid'").get()?.u, 1);
    assert.deepEqual({ ...db.prepare('SELECT * FROM users').get() }, { id: 1, name: 'old', admin: 1, oid: null });
    assert.deepEqual({ ...db.prepare('SELECT room_id, user_id, start_at, end_at FROM bookings').get() }, { room_id: 1, user_id: 1, start_at: 'a', end_at: 'b' });
    assert.deepEqual({ ...db.prepare('SELECT token, user_id, expires_at FROM sessions').get() }, { token: 'tok', user_id: 1, expires_at: null });
    db.close();
  }
});

test('a fresh database has no pass column', () => {
  const db = openDb(':memory:');
  assert.deepEqual((db.prepare("SELECT name FROM pragma_table_info('users')").all() as { name: string }[]).map((c) => c.name), ['id', 'name', 'admin', 'oid']);
});

type Claims = Record<string, unknown>;
const nowS = () => Math.floor(Date.now() / 1000);

/** An Entra-style v2 access token for /mcp; claims set to undefined are removed. */
function accessToken(issuer: OAuth2Issuer, claims: Claims = {}, kid?: string) {
  return issuer.buildToken({
    kid,
    scopesOrTransform: (_h, p) => {
      Object.assign(p, { aud: 'test-client', scp: 'Bookings.ReadWrite', oid: 'oid-mcp', name: 'Mcp User', ...claims });
      for (const k of Object.keys(p)) if (p[k] === undefined) delete p[k];
    },
  });
}

async function startMcp(t: TestContext, opts: { mcpScope?: string } = {}) {
  const ctx = await startOidc(t, opts);
  const post = (token: string | undefined, body: unknown, headers: Record<string, string> = {}) =>
    fetch(`${ctx.origin}/mcp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', ...(token && { Authorization: `Bearer ${token}` }), ...headers },
      body: typeof body === 'string' ? body : JSON.stringify(body),
    });
  const userRow = (oid: string) => {
    const row = ctx.db.prepare('SELECT id, name, admin FROM users WHERE oid = ?').get(oid);
    return row && { ...row };
  };
  return { ...ctx, post, userRow, token: (claims?: Claims, kid?: string) => accessToken(ctx.mock.issuer, claims, kid) };
}

test('mcp: missing or invalid bearer tokens get 401 with the resource metadata challenge', async (t) => {
  const { mock, db, origin, base, signIn, post, token } = await startMcp(t);
  const challenge = `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource", scope="api://test-client/Bookings.ReadWrite"`;
  const ping = { jsonrpc: '2.0', id: 1, method: 'ping' };

  const none = await post(undefined, ping);
  assert.equal(none.status, 401);
  assert.equal(none.headers.get('www-authenticate'), challenge);
  assert.deepEqual(await none.json(), { error: 'Unauthorized' });

  const forger = new OAuth2Issuer();
  forger.url = mock.issuer.url;
  await forger.keys.generate('RS256', { kid: mock.issuer.keys.get()?.kid });
  const session = (await signIn({ oid: 'oid-web', name: 'Web' })).token;
  const users = usersCount(db);
  const cases: [string, () => Promise<Response>][] = [
    ['other signing key', async () => post(await accessToken(forger), ping)],
    ['wrong iss', async () => post(await token({ iss: 'https://evil.example/' }), ping)],
    ['wrong aud', async () => post(await token({ aud: 'another-client' }), ping)],
    ['missing scp', async () => post(await token({ scp: undefined }), ping)],
    ['other scope only', async () => post(await token({ scp: 'User.Read' }), ping)],
    ['expired exp', async () => post(await token({ iat: nowS() - 600, nbf: nowS() - 600, exp: nowS() - 61 }), ping)],
    ['nbf in the future', async () => post(await token({ nbf: nowS() + 120 }), ping)],
    ['iat older than 15 minutes', async () => post(await token({ iat: nowS() - 16 * 60 }), ping)],
    ['missing iat', async () => post(await token({ iat: undefined }), ping)],
    ['missing oid', async () => post(await token({ oid: undefined }), ping)],
    ['malformed token', () => post('not-a-jwt', ping)],
    ['malformed segments', () => post('a.b.c', ping)],
    ['alg none', async () => {
      const [, payload] = (await token()).split('.');
      const header = Buffer.from(JSON.stringify({ alg: 'none', kid: mock.issuer.keys.get()?.kid })).toString('base64url');
      return post(`${header}.${payload}.`, ping);
    }],
    ['basic auth', () => post(undefined, ping, { Authorization: 'Basic dXNlcjpwYXNz' })],
    ['session cookie instead of bearer', () => post(undefined, ping, { Cookie: `session=${session}` })],
  ];
  for (const [name, run] of cases) {
    const res = await run();
    assert.equal(res.status, 401, name);
    assert.equal(res.headers.get('www-authenticate'), challenge, name);
    assert.deepEqual(await res.json(), { error: 'Unauthorized' }, name);
  }
  assert.equal(usersCount(db), users, 'no user created by rejected tokens');

  const ok = await post(await token({ iat: nowS() - 14 * 60, exp: nowS() - 30 }), ping, { 'MCP-Protocol-Version': '2025-11-25' });
  assert.notEqual(ok.status, 401, 'within the 60 s skew and 15 minute age');

  const valid = await token();
  for (const path of ['/me', '/bookings?from=2030-01-01T00:00Z&to=2030-01-02T00:00Z', '/rooms']) {
    const res = await fetch(base + path, { headers: { Authorization: `Bearer ${valid}` } });
    assert.equal(res.status, 401, `REST ${path} ignores bearer tokens`);
    assert.deepEqual(await res.json(), { error: 'Not logged in' });
  }
});

test('mcp: signing keys are cached and refetched at most once a minute', async (t) => {
  const { mock, post, token } = await startMcp(t);
  const ping = { jsonrpc: '2.0', id: 1, method: 'ping' };
  const headers = { 'MCP-Protocol-Version': '2025-11-25' };
  assert.notEqual((await post(await token(), ping, headers)).status, 401);
  await mock.issuer.keys.generate('RS256', { kid: 'rotated' });
  assert.equal((await post(await token({}, 'rotated'), ping, headers)).status, 401, 'unknown kid within a minute of the last fetch');
});

test('mcp: protected resource metadata is public', async (t) => {
  const { mock, origin } = await startMcp(t);
  const res = await fetch(`${origin}/.well-known/oauth-protected-resource`);
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), {
    resource: `${origin}/mcp`,
    authorization_servers: [mock.issuer.url],
    scopes_supported: ['api://test-client/Bookings.ReadWrite'],
    bearer_methods_supported: ['header'],
  });
  assert.equal((await fetch(`${origin}/.well-known/oauth-protected-resource`, { method: 'POST' })).status, 401, 'only GET is public');

  const custom = await startMcp(t, { mcpScope: 'api://custom-app/Bookings.ReadWrite' });
  const meta = await (await fetch(`${custom.origin}/.well-known/oauth-protected-resource`)).json();
  assert.deepEqual(meta.scopes_supported, ['api://custom-app/Bookings.ReadWrite']);
  const challenge = (await custom.post(undefined, {})).headers.get('www-authenticate');
  assert.equal(challenge, `Bearer resource_metadata="${custom.origin}/.well-known/oauth-protected-resource", scope="api://custom-app/Bookings.ReadWrite"`);
});

test('mcp: a valid token creates and updates the user from oid, name and roles', async (t) => {
  const { db, post, token, userRow } = await startMcp(t);
  const ping = { jsonrpc: '2.0', id: 1, method: 'ping' };
  const headers = { 'MCP-Protocol-Version': '2025-11-25' };
  const users = usersCount(db);
  assert.notEqual((await post(await token({ oid: 'oid-new', name: 'New User', roles: ['Admin'] }), ping, headers)).status, 401);
  const created = userRow('oid-new');
  assert.deepEqual({ name: created?.name, admin: created?.admin }, { name: 'New User', admin: 1 });
  assert.equal(usersCount(db), users + 1);
  await post(await token({ oid: 'oid-new', name: 'New User' }), ping, headers);
  assert.deepEqual(userRow('oid-new'), { ...created, admin: 0 }, 'same user, admin removed without the role');
  assert.equal(usersCount(db), users + 1);
});

const MODERN = '2026-07-28';
const modernMeta = { 'io.modelcontextprotocol/protocolVersion': MODERN, 'io.modelcontextprotocol/clientCapabilities': {}, 'io.modelcontextprotocol/clientInfo': { name: 'test', version: '1' } };
/** A 2026-07-28 request: per-request _meta plus the matching MCP-Protocol-Version, Mcp-Method and Mcp-Name headers. */
function modernRequest(method: string, params: Claims = {}, id: number | null = 1) {
  const headers: Record<string, string> = { 'MCP-Protocol-Version': MODERN, 'Mcp-Method': method };
  if (typeof params.name === 'string') headers['Mcp-Name'] = params.name;
  return { body: { jsonrpc: '2.0', ...(id !== null && { id }), method, params: { ...params, _meta: modernMeta } }, headers };
}
const LEGACY_HEADERS = { 'MCP-Protocol-Version': '2025-11-25' };

test('mcp: protocol versions, lifecycle and JSON-RPC errors', async (t) => {
  const { origin, post, token } = await startMcp(t);
  const tok = await token();
  const rpc = async (body: unknown, headers: Record<string, string> = {}) => {
    const res = await post(tok, body, headers);
    const text = await res.text();
    return { status: res.status, data: text ? JSON.parse(text) : undefined, contentType: res.headers.get('content-type') };
  };

  const init = await rpc({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'test', version: '1' } } });
  assert.equal(init.status, 200);
  assert.equal(init.contentType, 'application/json');
  assert.deepEqual(init.data, { jsonrpc: '2.0', id: 1, result: { protocolVersion: '2025-11-25', capabilities: { tools: {} }, serverInfo: { name: 'desk-booking', version: '1.0.0' } } });
  const old = await rpc({ jsonrpc: '2.0', id: 2, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {} } });
  assert.equal(old.data.result.protocolVersion, '2025-06-18');
  const unknownInit = await rpc({ jsonrpc: '2.0', id: 3, method: 'initialize', params: { protocolVersion: '1900-01-01', capabilities: {} } });
  assert.equal(unknownInit.data.result.protocolVersion, '2025-11-25', 'legacy negotiation answers with a supported version');
  const initialized = await rpc({ jsonrpc: '2.0', method: 'notifications/initialized' }, LEGACY_HEADERS);
  assert.deepEqual([initialized.status, initialized.data], [202, undefined]);

  const legacyList = await rpc({ jsonrpc: '2.0', id: 4, method: 'tools/list' }, LEGACY_HEADERS);
  assert.equal(legacyList.status, 200);
  assert.ok(Array.isArray(legacyList.data.result.tools));
  assert.equal(legacyList.data.result._meta, undefined);
  assert.deepEqual((await rpc({ jsonrpc: '2.0', id: 'p', method: 'ping' }, { 'MCP-Protocol-Version': '2025-06-18' })).data, { jsonrpc: '2.0', id: 'p', result: {} });

  const ping = modernRequest('ping');
  assert.deepEqual(await rpc(ping.body, ping.headers), {
    status: 200, contentType: 'application/json',
    data: { jsonrpc: '2.0', id: 1, result: { _meta: { 'io.modelcontextprotocol/serverInfo': { name: 'desk-booking', version: '1.0.0' } } } },
  });
  const list = modernRequest('tools/list');
  assert.equal((await rpc(list.body, list.headers)).status, 200, 'stateless: no initialize needed');
  const note = modernRequest('notifications/cancelled', { requestId: 1 }, null);
  assert.equal((await rpc(note.body, note.headers)).status, 202);

  const headerMismatch = async (headers: Record<string, string | undefined>, body: unknown = ping.body) => {
    const r = await rpc(body, Object.fromEntries(Object.entries(headers).filter(([, v]) => v !== undefined)) as Record<string, string>);
    assert.equal(r.status, 400, JSON.stringify(headers));
    assert.equal(r.data.error.code, -32020, JSON.stringify(headers));
    return r.data.error.message as string;
  };
  assert.equal(await headerMismatch({ ...ping.headers, 'Mcp-Method': 'tools/list' }), "Header mismatch: Mcp-Method header value 'tools/list' does not match body value 'ping'");
  await headerMismatch({ ...ping.headers, 'Mcp-Method': undefined });
  await headerMismatch({ ...ping.headers, 'MCP-Protocol-Version': undefined });
  await headerMismatch({ 'Mcp-Method': 'ping', 'MCP-Protocol-Version': '2025-11-25' });
  const call = modernRequest('tools/call', { name: 'list_rooms', arguments: {} });
  await headerMismatch({ ...call.headers, 'Mcp-Name': 'delete_room' }, call.body);
  await headerMismatch({ ...call.headers, 'Mcp-Name': undefined }, call.body);
  await headerMismatch({}, { jsonrpc: '2.0', id: 9, method: 'tools/list' });

  const unsupported = await rpc({ ...ping.body, params: { _meta: { ...modernMeta, 'io.modelcontextprotocol/protocolVersion': '1900-01-01' } } }, { ...ping.headers, 'MCP-Protocol-Version': '1900-01-01' });
  assert.deepEqual([unsupported.status, unsupported.data], [400, { jsonrpc: '2.0', id: 1, error: { code: -32022, message: 'Unsupported protocol version', data: { supported: ['2026-07-28', '2025-11-25', '2025-06-18'], requested: '1900-01-01' } } }]);
  const unsupportedLegacy = await rpc({ jsonrpc: '2.0', id: 5, method: 'tools/list' }, { 'MCP-Protocol-Version': '2024-11-05' });
  assert.deepEqual([unsupportedLegacy.status, unsupportedLegacy.data.error.code, unsupportedLegacy.data.error.data.requested], [400, -32022, '2024-11-05']);
  const noCaps = await rpc({ ...ping.body, params: { _meta: { 'io.modelcontextprotocol/protocolVersion': MODERN } } }, ping.headers);
  assert.deepEqual([noCaps.status, noCaps.data.error.code], [400, -32602]);

  const unknown = modernRequest('resources/list');
  assert.deepEqual(await rpc(unknown.body, unknown.headers), { status: 404, contentType: 'application/json', data: { jsonrpc: '2.0', id: 1, error: { code: -32601, message: 'Method not found' } } });
  const unknownLegacy = await rpc({ jsonrpc: '2.0', id: 6, method: 'prompts/list' }, LEGACY_HEADERS);
  assert.deepEqual([unknownLegacy.status, unknownLegacy.data.error.code], [200, -32601], 'legacy clients read a 404 as a lost session');

  const parse = await rpc('{"jsonrpc": "2.0", "id": 1, "method": ', LEGACY_HEADERS);
  assert.deepEqual([parse.status, parse.data], [400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }]);
  for (const bad of [[{ jsonrpc: '2.0', id: 1, method: 'ping' }], { id: 1, method: 'ping' }, { jsonrpc: '2.0', id: null, method: 'ping' }, { jsonrpc: '2.0', id: 1, result: {} }]) {
    const r = await rpc(bad, LEGACY_HEADERS);
    assert.deepEqual([r.status, r.data.error.code], [400, -32600], JSON.stringify(bad));
  }

  for (const method of ['GET', 'DELETE', 'PUT']) {
    const res = await fetch(`${origin}/mcp`, { method, headers: { Authorization: `Bearer ${tok}` } });
    assert.equal(res.status, 405, method);
    assert.equal(res.headers.get('allow'), 'POST');
  }
  assert.equal((await fetch(`${origin}/mcp`)).status, 405, 'GET without a token');

  const big = await post(tok, { jsonrpc: '2.0', id: 7, method: 'ping', params: { pad: 'x'.repeat(110_000) } }, LEGACY_HEADERS);
  assert.equal(big.status, 413);
  assert.equal((await big.json()).error.code, -32600);
});
