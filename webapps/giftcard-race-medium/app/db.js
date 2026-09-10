const Database = require('better-sqlite3')

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    balance  REAL NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS codes (
    code  TEXT PRIMARY KEY,
    value REAL NOT NULL,
    used  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS redemption_requests (
    idempotency_key TEXT PRIMARY KEY,
    code            TEXT NOT NULL,
    user_id         INTEGER NOT NULL,
    status          TEXT NOT NULL DEFAULT 'processing',
    created_at      REAL NOT NULL,
    resolved_at     REAL
);

CREATE TABLE IF NOT EXISTS purchases (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL,
    item_id      TEXT NOT NULL,
    price        REAL NOT NULL,
    purchased_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS scoring_events (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    metric TEXT NOT NULL,
    detail TEXT,
    ts     REAL NOT NULL
);
`

function seedCodes(db) {
  db.prepare('INSERT OR REPLACE INTO codes (code, value, used) VALUES (?, ?, 0)').run('WELCOME50', 50)
}

function createDb(dbPath) {
  const db = new Database(dbPath)
  db.pragma('journal_mode = WAL')
  db.exec(SCHEMA)
  seedCodes(db)
  return db
}

function resetDb(db) {
  db.exec('DELETE FROM scoring_events')
  db.exec('DELETE FROM purchases')
  db.exec('DELETE FROM redemption_requests')
  db.exec('DELETE FROM users')
  seedCodes(db)
}

module.exports = { createDb, resetDb }
