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
  // Existing databases predate these columns; CREATE TABLE IF NOT EXISTS does not add them.
  const hasColumn = (table: string, column: string) => !!db.prepare('SELECT 1 FROM pragma_table_info(?) WHERE name = ?').get(table, column);
  if (!hasColumn('users', 'oid')) db.exec('ALTER TABLE users ADD COLUMN oid TEXT');
  if (!hasColumn('sessions', 'expires_at')) db.exec('ALTER TABLE sessions ADD COLUMN expires_at INTEGER');
  db.exec('CREATE UNIQUE INDEX IF NOT EXISTS users_oid ON users (oid)');
  return db;
}

export function hashPassword(password: string) {
  const salt = randomBytes(16).toString('hex');
  return `${salt}:${scryptSync(password, salt, 64).toString('hex')}`;
}

export function checkPassword(password: string, stored: string) {
  const [salt, hash = ''] = stored.split(':');
  const expected = Buffer.from(hash, 'hex');
  // OIDC users store pass = '', which must fail instead of throwing in timingSafeEqual.
  if (!salt || expected.length !== 64) return false;
  return timingSafeEqual(expected, scryptSync(password, salt, 64));
}

/** Creates the `admin` account on first run so someone can manage rooms. */
export function seedAdmin(db: DatabaseSync, password = process.env.ADMIN_PASSWORD) {
  if (db.prepare('SELECT 1 FROM users WHERE admin = 1').get()) return;
  const pw = password ?? randomBytes(9).toString('base64url');
  db.prepare('INSERT INTO users (name, pass, admin) VALUES (?, ?, 1)').run('admin', hashPassword(pw));
  if (!password) console.log(`Created admin account -> name: admin, password: ${pw}`);
}
