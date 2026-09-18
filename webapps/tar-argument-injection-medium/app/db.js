const Database = require('better-sqlite3')

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email    TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cases (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id          INTEGER NOT NULL,
    case_number      TEXT NOT NULL,
    last_compiled_at REAL
);

CREATE TABLE IF NOT EXISTS documents (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id  INTEGER NOT NULL,
    filename TEXT NOT NULL,
    content  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS telemetry_reports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    payload     TEXT NOT NULL,
    reported_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS archive_access_log (
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

function randomCaseNumber() {
  const digits = Math.floor(100000 + Math.random() * 900000)
  return `ASH-${digits}`
}

function createCaseForUser(db, userId) {
  db.prepare('INSERT INTO cases (user_id, case_number, last_compiled_at) VALUES (?, ?, NULL)').run(
    userId,
    randomCaseNumber()
  )
}

function initDb(dbPath) {
  const db = new Database(dbPath)
  db.pragma('journal_mode = WAL')
  db.exec(SCHEMA)
  return db
}

function resetDb(db) {
  db.exec('DELETE FROM scoring_events')
  db.exec('DELETE FROM archive_access_log')
  db.exec('DELETE FROM telemetry_reports')
  db.exec('DELETE FROM documents')
  db.exec('DELETE FROM cases')
  db.exec('DELETE FROM users')
}

module.exports = { initDb, resetDb, createCaseForUser }
