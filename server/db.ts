import { DatabaseSync } from 'node:sqlite';

export function openDb(path: string) {
  const db = new DatabaseSync(path);
  db.exec(`
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL COLLATE NOCASE,
      admin INTEGER NOT NULL DEFAULT 0);
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
  // Password login is gone; dropping the column deletes the old password hashes.
  if (hasColumn('users', 'pass')) db.exec('ALTER TABLE users DROP COLUMN pass');
  db.exec('CREATE UNIQUE INDEX IF NOT EXISTS users_oid ON users (oid)');
  return db;
}

export function ensureRoom(db: DatabaseSync, name: string) {
  db.prepare('INSERT INTO rooms (name) SELECT ? WHERE NOT EXISTS (SELECT 1 FROM rooms)').run(name);
}
