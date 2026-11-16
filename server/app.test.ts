import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { openDb, seedAdmin } from './db.ts';
import { createHandler } from './app.ts';

function startServer(t: TestContext) {
  const db = openDb(':memory:');
  seedAdmin(db, 'admin-pass');
  const server = createServer(createHandler(db)).listen(0);
  t.after(() => server.close());
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}/api`;
}

const sessionToken = (res: Response) => res.headers.get('set-cookie')?.match(/^session=([^;]*)/)?.[1] ?? '';

test('booking flow', async (t) => {
  const base = startServer(t);

  const call = async (method: string, path: string, token?: string, body?: object) => {
    const res = await fetch(base + path, {
      method,
      headers: token ? { Cookie: `session=${token}` } : {},
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
  const base = startServer(t);
  const post = (path: string, headers: Record<string, string>, body?: object) =>
    fetch(base + path, { method: 'POST', headers, body: body && JSON.stringify(body) });
  const me = (headers: Record<string, string>) => fetch(base + '/me', { headers });

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
