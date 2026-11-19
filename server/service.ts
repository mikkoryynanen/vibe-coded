import type { IncomingMessage } from 'node:http';
import type { DatabaseSync } from 'node:sqlite';

export type ActingUser = { id: number; name: string; admin: boolean };
export type Body = Record<string, unknown>;

export class HttpError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export async function readJson(req: IncomingMessage): Promise<Body> {
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

export function text(v: unknown, field: string, min = 1, max = 50) {
  if (typeof v !== 'string' || v.trim().length < min || v.trim().length > max)
    throw new HttpError(400, `${field} must be ${min}-${max} characters`);
  return v.trim();
}

/** Normalizes to UTC ISO strings so SQLite string comparison orders times correctly. */
export function time(v: unknown, field: string) {
  const d = typeof v === 'string' ? new Date(v) : null;
  if (!d || isNaN(d.getTime())) throw new HttpError(400, `${field} must be a valid date/time`);
  return d.toISOString();
}

export const requireAdmin = (user: ActingUser) => { if (!user.admin) throw new HttpError(403, 'Admins only'); };

export type Service = ReturnType<typeof createService>;

export function createService(db: DatabaseSync) {
  const q = {
    userByName: db.prepare('SELECT id FROM users WHERE name = ?'),
    userByOid: db.prepare('SELECT id, admin FROM users WHERE oid = ?'),
    addOidcUser: db.prepare('INSERT INTO users (name, admin, oid) VALUES (?, ?, ?)'),
    updateOidcUser: db.prepare('UPDATE users SET name = ?, admin = ? WHERE id = ?'),
    rooms: db.prepare('SELECT id, name FROM rooms ORDER BY name'),
    room: db.prepare('SELECT id FROM rooms WHERE id = ?'),
    addRoom: db.prepare('INSERT INTO rooms (name) VALUES (?)'),
    renameRoom: db.prepare('UPDATE rooms SET name = ? WHERE id = ?'),
    delRoom: db.prepare('DELETE FROM rooms WHERE id = ?'),
    bookings: db.prepare(`
      SELECT b.id, b.room_id AS roomId, b.user_id AS userId, u.name AS userName, b.start_at AS start, b.end_at AS end
      FROM bookings b JOIN users u ON u.id = b.user_id
      WHERE b.start_at < ? AND b.end_at > ? ORDER BY b.start_at`),
    myBookings: db.prepare(`
      SELECT b.id, b.room_id AS roomId, r.name AS roomName, b.start_at AS start, b.end_at AS end
      FROM bookings b JOIN rooms r ON r.id = b.room_id
      WHERE b.user_id = ? AND b.end_at > ? ORDER BY b.start_at`),
    freeRooms: db.prepare(`
      SELECT r.id, r.name FROM rooms r
      WHERE NOT EXISTS (SELECT 1 FROM bookings b WHERE b.room_id = r.id AND b.start_at < ? AND b.end_at > ?)
      ORDER BY r.name`),
    clash: db.prepare('SELECT 1 FROM bookings WHERE room_id = ? AND start_at < ? AND end_at > ?'),
    addBooking: db.prepare('INSERT INTO bookings (room_id, user_id, start_at, end_at) VALUES (?, ?, ?, ?)'),
    booking: db.prepare('SELECT user_id AS userId FROM bookings WHERE id = ?'),
    delBooking: db.prepare('DELETE FROM bookings WHERE id = ?'),
  };

  const range = (start: unknown, end: unknown) => {
    const s = time(start, 'Start');
    const e = time(end, 'End');
    if (e <= s) throw new HttpError(400, 'End must be after start');
    return [s, e];
  };

  return {
    /** Creates or updates the user for verified Entra claims. With `lowerAdminOnly` (bearer tokens) a stored admin flag is never raised. */
    upsertOidcUser(claims: Record<string, unknown>, opts: { lowerAdminOnly?: boolean } = {}): ActingUser {
      if (typeof claims.oid !== 'string' || !claims.oid) throw new Error('Token has no oid claim');
      const oid = claims.oid;
      const claimed = typeof claims.name === 'string' && claims.name.trim() ? claims.name : claims.preferred_username;
      let name = typeof claimed === 'string' ? claimed.trim().slice(0, 50) : '';
      if (!name) throw new Error('Token has no name or preferred_username claim');
      const admin = Array.isArray(claims.roles) && claims.roles.includes('Admin');
      const existing = q.userByOid.get(oid) as { id: number; admin: number } | undefined;
      const taken = q.userByName.get(name) as { id: number } | undefined;
      if (taken && taken.id !== existing?.id) name = `${name} (${oid.slice(0, 8)})`;
      let id = existing?.id;
      if (id) q.updateOidcUser.run(name, admin && !(opts.lowerAdminOnly && !existing?.admin) ? 1 : 0, id);
      else id = Number(q.addOidcUser.run(name, admin ? 1 : 0, oid).lastInsertRowid);
      return { id, name, admin };
    },

    listRooms: () => q.rooms.all() as { id: number; name: string }[],

    addRoom(user: ActingUser, name: unknown) {
      requireAdmin(user);
      return { id: Number(q.addRoom.run(text(name, 'Room name')).lastInsertRowid) };
    },

    renameRoom(user: ActingUser, roomId: unknown, name: unknown) {
      requireAdmin(user);
      const n = text(name, 'Room name');
      const id = Number(roomId);
      if (!Number.isInteger(id) || !q.renameRoom.run(n, id).changes) throw new HttpError(404, 'Room not found');
    },

    deleteRoom(user: ActingUser, roomId: unknown) {
      requireAdmin(user);
      const id = Number(roomId);
      if (!Number.isInteger(id) || !q.delRoom.run(id).changes) throw new HttpError(404, 'Room not found');
    },

    listBookings(from: unknown, to: unknown) {
      const f = time(from, 'from');
      return q.bookings.all(time(to, 'to'), f);
    },

    myBookings(user: ActingUser) {
      return q.myBookings.all(user.id, new Date().toISOString());
    },

    findFreeRooms(start: unknown, end: unknown) {
      const [s, e] = range(start, end);
      return q.freeRooms.all(e, s);
    },

    bookRoom(user: ActingUser, roomId: unknown, start: unknown, end: unknown) {
      const rid = Number(roomId);
      const [s, e] = range(start, end);
      if (!Number.isInteger(rid) || !q.room.get(rid)) throw new HttpError(404, 'Room not found');
      // Check and insert run synchronously with no await between, so no other request can interleave.
      if (q.clash.get(rid, e, s)) throw new HttpError(409, 'That room is already booked in this time');
      return { id: Number(q.addBooking.run(rid, user.id, s, e).lastInsertRowid) };
    },

    cancelBooking(user: ActingUser, bookingId: unknown) {
      const id = Number(bookingId);
      const b = Number.isInteger(id) ? (q.booking.get(id) as { userId: number } | undefined) : undefined;
      if (!b) throw new HttpError(404, 'Booking not found');
      if (b.userId !== user.id && !user.admin) throw new HttpError(403, 'You can only cancel your own bookings');
      q.delBooking.run(id);
    },
  };
}
