import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { openDb, seedAdmin } from './db.ts';
import { createHandler } from './app.ts';

test('booking flow', async (t) => {
  const db = openDb(':memory:');
  seedAdmin(db, 'admin-pass');
  const server = createServer(createHandler(db)).listen(0);
  t.after(() => server.close());
  const base = `http://localhost:${(server.address() as AddressInfo).port}/api`;

  const call = async (method: string, path: string, token?: string, body?: object) => {
    const res = await fetch(base + path, {
      method,
      headers: token ? { Authorization: `Bearer ${token}` } : {},
      body: body && JSON.stringify(body),
    });
    return { status: res.status, data: await res.json() };
  };

  assert.equal((await call('GET', '/rooms')).status, 401);
  assert.equal((await call('POST', '/login', undefined, { name: 'admin', password: 'nope' })).status, 401);

  const admin = (await call('POST', '/login', undefined, { name: 'admin', password: 'admin-pass' })).data.token;
  assert.equal((await call('POST', '/register', undefined, { name: 'eve', password: 'password' })).status, 401, 'no self-registration');
  assert.equal((await call('POST', '/users', undefined, { name: 'eve', password: 'password' })).status, 401);
  assert.equal((await call('POST', '/users', admin, { name: 'alice', password: 'pass' })).status, 200);
  assert.equal((await call('POST', '/users', admin, { name: 'bob', password: 'password2' })).status, 200);
  assert.equal((await call('POST', '/users', admin, { name: 'Alice', password: 'password3' })).status, 409);
  assert.equal((await call('POST', '/users', admin, { name: 'carol', password: 'abc' })).status, 400);
  const login = async (name: string, password: string) => (await call('POST', '/login', undefined, { name, password })).data.token;
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
