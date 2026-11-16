import type { IncomingMessage, ServerResponse } from 'node:http';
import type { DatabaseSync } from 'node:sqlite';
import { randomBytes } from 'node:crypto';
import { checkPassword, hashPassword } from './db.ts';

type User = { id: number; name: string; admin: number };
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

export function createHandler(db: DatabaseSync) {
  const q = {
    userByName: db.prepare('SELECT id, name, admin, pass FROM users WHERE name = ?'),
    userByToken: db.prepare('SELECT u.id, u.name, u.admin FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?'),
    addUser: db.prepare('INSERT INTO users (name, pass) VALUES (?, ?)'),
    addSession: db.prepare('INSERT INTO sessions (token, user_id) VALUES (?, ?)'),
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

  // shortcut: sessions never expire, add an expires_at column if tokens must time out.
  function startSession(user: { id: number; name: string; admin: number }) {
    const token = randomBytes(32).toString('base64url');
    q.addSession.run(token, user.id);
    return { token, user: { id: user.id, name: user.name, admin: !!user.admin } };
  }

  async function route(req: IncomingMessage, method: string, path: string, url: URL): Promise<unknown> {
    const body = method === 'POST' || method === 'PATCH' ? await readJson(req) : {};

    if (method === 'POST' && path === '/api/login') {
      const row = q.userByName.get(String(body.name ?? '')) as (User & { pass: string }) | undefined;
      if (!row || !checkPassword(String(body.password ?? ''), row.pass)) throw new HttpError(401, 'Wrong name or password');
      return startSession(row);
    }

    const token = req.headers.authorization?.replace(/^Bearer /, '') ?? '';
    const user = q.userByToken.get(token) as User | undefined;
    if (!user) throw new HttpError(401, 'Not logged in');
    const requireAdmin = () => { if (!user.admin) throw new HttpError(403, 'Admins only'); };

    if (method === 'GET' && path === '/api/me') return { id: user.id, name: user.name, admin: !!user.admin };
    if (method === 'POST' && path === '/api/logout') return q.delSession.run(token), {};

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
      result = await route(req, req.method ?? 'GET', url.pathname, url);
    } catch (e) {
      if (e instanceof HttpError) [status, result] = [e.status, { error: e.message }];
      else if (e instanceof Error && e.message.includes('UNIQUE')) [status, result] = [409, { error: 'That name is already taken' }];
      else {
        console.error(e);
        [status, result] = [500, { error: 'Server error' }];
      }
    }
    res.writeHead(status, { 'Content-Type': 'application/json' }).end(JSON.stringify(result));
  };
}
