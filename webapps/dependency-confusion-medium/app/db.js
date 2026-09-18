const Database = require('better-sqlite3')

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email    TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS shipments (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    reference   TEXT NOT NULL,
    destination TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'in_transit'
);

CREATE TABLE IF NOT EXISTS telemetry_reports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    payload     TEXT NOT NULL,
    reported_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS billing_access_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    accessed_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS scoring_events (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    metric TEXT NOT NULL,
    detail TEXT,
    ts     REAL NOT NULL
);
`

const SHIPMENTS_FOR_NEW_USER = [
  { reference: 'Inbound — Rotterdam', destination: 'Rotterdam' },
  { reference: 'Outbound — Newark', destination: 'Newark' },
]

function initDb(dbPath) {
  const db = new Database(dbPath)
  db.pragma('journal_mode = WAL')
  db.exec(SCHEMA)
  return db
}

function createShipmentsForUser(db, userId) {
  const insert = db.prepare(
    'INSERT INTO shipments (user_id, reference, destination, status) VALUES (?, ?, ?, ?)'
  )
  for (const { reference, destination } of SHIPMENTS_FOR_NEW_USER) {
    insert.run(userId, reference, destination, 'in_transit')
  }
}

function resetDb(db) {
  db.exec('DELETE FROM scoring_events')
  db.exec('DELETE FROM billing_access_log')
  db.exec('DELETE FROM telemetry_reports')
  db.exec('DELETE FROM shipments')
  db.exec('DELETE FROM users')
}

module.exports = { initDb, resetDb, createShipmentsForUser }
