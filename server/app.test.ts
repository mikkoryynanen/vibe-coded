import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { OAuth2Issuer, OAuth2Server } from 'oauth2-mock-server';
import { openDb, seedAdmin } from './db.ts';
import { createHandler } from './app.ts';

function startServer(t: TestContext) {
  const db = openDb(':memory:');
  seedAdmin(db, 'admin-pass');
  const server = createServer(createHandler(db)).listen(0);
  t.after(() => server.close());
  return { db, base: `http://127.0.0.1:${(server.address() as AddressInfo).port}/api` };
}

const sessionToken = (res: Response) => res.headers.get('set-cookie')?.match(/^session=([^;]*)/)?.[1] ?? '';

test('booking flow', async (t) => {
  const { base } = startServer(t);

  const call = async (method: string, path: string, token?: string, body?: object) => {
    const res = await fetch(base + path, {
      method,
      headers: { 'Content-Type': 'application/json', ...(token && { Cookie: `session=${token}` }) },
      body: body && JSON.stringify(body),
    });
    return { status: res.status, data: await res.json(), token: sessionToken(res) };
  };

  assert.equal((await call('GET', '/rooms')).status, 401);
  assert.equal((await call('POST', '/login', undefined, { name: 'admin', password: 'nope' })).status, 401);

  const admin = (await call('POST', '/login', undefined, { name: 'admin', password: 'admin-pass' })).token;
  assert.equal((await call('POST', '/register', undefined, { name: 'eve', password: 'password' })).status, 401, 'no self-registration');
  assert.equal((await call('POST', '/users', undefined, { name: 'eve', password: 'password' })).status, 401);
  assert.equal((await call('POST', '/users', admin, { name: 'alice', password: 'pass' })).status, 200);
  assert.equal((await call('POST', '/users', admin, { name: 'bob', password: 'password2' })).status, 200);
  assert.equal((await call('POST', '/users', admin, { name: 'Alice', password: 'password3' })).status, 409);
  assert.equal((await call('POST', '/users', admin, { name: 'carol', password: 'abc' })).status, 400);
  const login = async (name: string, password: string) => (await call('POST', '/login', undefined, { name, password })).token;
  const alice = await login('alice', 'pass');
  const bob = await login('bob', 'password2');
  assert.equal((await call('POST', '/users', alice, { name: 'mallory', password: 'password' })).status, 403);

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
  const { base, db } = startServer(t);
  const post = (path: string, headers: Record<string, string>, body?: object) =>
    fetch(base + path, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: body && JSON.stringify(body) });
  const me = (headers: Record<string, string>) => fetch(base + '/me', { headers });

  const creds = JSON.stringify({ name: 'admin', password: 'admin-pass' });
  for (const type of [undefined, 'text/plain', 'application/x-www-form-urlencoded', 'multipart/form-data; boundary=x', 'application/jsonx']) {
    const r = await fetch(base + '/login', { method: 'POST', headers: type ? { 'Content-Type': type } : {}, body: new Blob([creds]) });
    assert.ok(r.status >= 400 && r.status < 500, `${type}: ${r.status}`);
    assert.equal(r.headers.get('set-cookie'), null, `${type} sets no cookie`);
  }
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM sessions').get()?.n, 0, 'no session rows from rejected logins');
  const charset = await post('/login', { 'Content-Type': 'application/json; charset=utf-8' }, { name: 'admin', password: 'admin-pass' });
  assert.equal(charset.status, 200);
  assert.ok(sessionToken(charset));

  const bad = await post('/login', {}, { name: 'admin', password: 'nope' });
  assert.equal(bad.status, 401);
  assert.equal(bad.headers.get('set-cookie'), null);

  const login = await post('/login', {}, { name: 'admin', password: 'admin-pass' });
  assert.equal(login.status, 200);
  const body = await login.json();
  assert.equal(body.user.name, 'admin');
  assert.equal('token' in body, false, 'token stays out of the body');
  const cookie = login.headers.get('set-cookie') ?? '';
  for (const part of ['HttpOnly', 'SameSite=Lax', 'Path=/', 'Max-Age=2592000', 'Secure'])
    assert.ok(cookie.split('; ').includes(part), `login cookie has ${part}: ${cookie}`);
  const token = sessionToken(login);
  assert.ok(token);

  const ok = await me({ Cookie: `other=1; session=${token}` });
  assert.equal(ok.status, 200);
  assert.equal((await ok.json()).name, 'admin');
  for (const headers of [{}, { Cookie: 'session=bogus' }, { Cookie: 'session=' }, { Authorization: `Bearer ${token}` }] as Record<string, string>[]) {
    const r = await me(headers);
    assert.equal(r.status, 401, JSON.stringify(headers));
    assert.equal((await r.json()).error, 'Not logged in');
  }

  const out = await post('/logout', { Cookie: `session=${token}` });
  assert.equal(out.status, 200);
  const cleared = out.headers.get('set-cookie') ?? '';
  assert.ok(cleared.startsWith('session=;'), cleared);
  assert.ok(cleared.includes('Max-Age=0') && cleared.includes('Secure'), cleared);
  assert.equal((await me({ Cookie: `session=${token}` })).status, 401);

  const again = await post('/logout', { Cookie: `session=${token}` });
  assert.equal(again.status, 401, 'logout without a valid session stays 401');
  assert.equal(again.headers.get('set-cookie'), null);
});

const usersCount = (db: DatabaseSync) => Number(db.prepare('SELECT COUNT(*) AS n FROM users').get()?.n);
const setCookie = (res: Response, name: string) => res.headers.getSetCookie().find((c) => c.startsWith(`${name}=`));
const cookieValue = (res: Response, name: string) => setCookie(res, name)?.match(/^[^=]+=([^;]*)/)?.[1] ?? '';

type Tamper = (cb: URL, flow: string) => string | null | Promise<string | null>;

async function startOidc(t: TestContext) {
  const mock = new OAuth2Server();
  await mock.issuer.keys.generate('RS256');
  await mock.start(0, 'localhost');
  t.after(() => mock.stop());
  let claims: Record<string, unknown> = {};
  mock.service.on('beforeTokenSigning', (token) => Object.assign(token.payload, claims));

  const db = openDb(':memory:');
  seedAdmin(db, 'admin-pass');
  const server = createServer().listen(0);
  t.after(() => server.close());
  const origin = `http://localhost:${(server.address() as AddressInfo).port}`;
  server.on('request', createHandler(db, { issuer: mock.issuer.url!, clientId: 'test-client', clientSecret: 'test-secret', redirectUri: `${origin}/api/callback` }));
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
  return { mock, db, base, signIn, call };
}

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
  assert.equal(db.prepare('SELECT pass FROM users WHERE oid = ?').get('oid-alice-1234')?.pass, '');

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

  const pw = await call('POST', '/login', undefined, { name: 'Alice Entra', password: 'anything' });
  assert.equal(pw.status, 401, 'password login on an OIDC user is 401, not 500');
  assert.equal(pw.res.headers.get('set-cookie'), null);
  assert.equal((await call('POST', '/login', undefined, { name: 'Alice Entra', password: '' })).status, 401);
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

  const pw = await call('POST', '/login', undefined, { name: 'admin', password: 'admin-pass' });
  const pwToken = cookieValue(pw.res, 'session');
  assert.equal(db.prepare('SELECT expires_at AS e FROM sessions WHERE token = ?').get(pwToken)?.e, null, 'password sessions keep no expiry');
  assert.equal((await call('GET', '/me', pwToken)).status, 200);
  assert.equal((await fetch(`${base}/me`)).status, 401);
});

test('non-admin oidc user is still bound by admin and ownership checks', async (t) => {
  const { signIn, call } = await startOidc(t);
  const admin = cookieValue((await call('POST', '/login', undefined, { name: 'admin', password: 'admin-pass' })).res, 'session');
  const roomId = (await call('POST', '/rooms', admin, { name: 'Desk 1' })).data.id;
  const adminBooking = (await call('POST', '/bookings', admin, { roomId, start: '2030-01-01T09:00Z', end: '2030-01-01T10:00Z' })).data.id;
  const { token } = await signIn({ oid: 'oid-bob', name: 'Bob', roles: ['Reader'] });
  assert.equal((await call('GET', '/me', token)).data.admin, false);
  assert.equal((await call('POST', '/rooms', token, { name: 'Desk 2' })).status, 403);
  assert.equal((await call('POST', '/users', token, { name: 'eve', password: 'password' })).status, 403);
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

test('oidc without config', async (t) => {
  const { base } = startServer(t);
  for (const path of ['/login', '/login?silent=1', '/callback?code=abc&state=def']) {
    const res = await fetch(base + path, { redirect: 'manual', headers: { Cookie: 'oidc=a.b.c.0' } });
    assert.equal(res.status, 302, path);
    assert.equal(res.headers.get('location'), '/?login_error=1', path);
    assert.equal(setCookie(res, 'session'), undefined, path);
  }
  const pw = await fetch(base + '/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: 'admin', password: 'admin-pass' }) });
  assert.equal(pw.status, 200, 'password login still works');
  const form = await fetch(base + '/login', { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: '{}' });
  assert.equal(form.status, 415);
});

test('openDb upgrades an old-schema database in place', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'booking-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'old.db');
  const old = new DatabaseSync(path);
  old.exec(`
    CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL COLLATE NOCASE, pass TEXT NOT NULL, admin INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE sessions (token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users ON DELETE CASCADE);
    INSERT INTO users (name, pass, admin) VALUES ('old', 'salt:hash', 1);
    INSERT INTO sessions (token, user_id) VALUES ('tok', 1);`);
  old.close();

  for (let i = 0; i < 2; i++) {
    const db = openDb(path);
    const cols = (table: string) => (db.prepare('SELECT name FROM pragma_table_info(?)').all(table) as { name: string }[]).map((c) => c.name);
    assert.ok(cols('users').includes('oid'));
    assert.ok(cols('sessions').includes('expires_at'));
    assert.equal(db.prepare("SELECT \"unique\" AS u FROM pragma_index_list('users') WHERE name = 'users_oid'").get()?.u, 1);
    assert.deepEqual({ ...db.prepare('SELECT name, pass, admin, oid FROM users').get() }, { name: 'old', pass: 'salt:hash', admin: 1, oid: null });
    assert.deepEqual({ ...db.prepare('SELECT token, user_id, expires_at FROM sessions').get() }, { token: 'tok', user_id: 1, expires_at: null });
    db.close();
  }
});
