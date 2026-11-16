import { DatabaseSync } from 'node:sqlite';
import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';

export function openDb(path: string) {
  const db = new DatabaseSync(path);
  db.exec(`
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL COLLATE NOCASE,
      pass TEXT NOT NULL, admin INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users ON DELETE CASCADE);
    CREATE TABLE IF NOT EXISTS rooms (
      id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL COLLATE NOCASE);
    CREATE TABLE IF NOT EXISTS bookings (
      id INTEGER PRIMARY KEY,
      room_id INTEGER NOT NULL REFERENCES rooms ON DELETE CASCADE,
      user_id INTEGER NOT NULL REFERENCES users ON DELETE CASCADE,
      start_at TEXT NOT NULL, end_at TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS bookings_room_time ON bookings (room_id, start_at);
  `);
  return db;
}

export function hashPassword(password: string) {
  const salt = randomBytes(16).toString('hex');
  return `${salt}:${scryptSync(password, salt, 64).toString('hex')}`;
}

export function checkPassword(password: string, stored: string) {
  const [salt, hash] = stored.split(':');
  return timingSafeEqual(Buffer.from(hash, 'hex'), scryptSync(password, salt, 64));
}

/** Creates the `admin` account on first run so someone can manage rooms. */
export function seedAdmin(db: DatabaseSync, password = process.env.ADMIN_PASSWORD) {
  if (db.prepare('SELECT 1 FROM users WHERE admin = 1').get()) return;
  const pw = password ?? randomBytes(9).toString('base64url');
  db.prepare('INSERT INTO users (name, pass, admin) VALUES (?, ?, 1)').run('admin', hashPassword(pw));
  if (!password) console.log(`Created admin account -> name: admin, password: ${pw}`);
}
