const Database = require('better-sqlite3')
const crypto = require('crypto')

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email    TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role     TEXT NOT NULL DEFAULT 'member'
);

CREATE TABLE IF NOT EXISTS reports (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    title   TEXT NOT NULL,
    content TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scoring_events (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    metric TEXT NOT NULL,
    detail TEXT,
    ts     REAL NOT NULL
);
`

const ADMIN_EMAIL = 'ops-admin@wrenlake.local'
const ADMIN_USERNAME = 'ops-admin'

const REPORT_TITLE = 'Q3 Operations & Headcount Summary'
const REPORT_CONTENT = `Staffing is steady at 42 FTEs across the ops team, one open req for a
support lead pending finance approval. Budget spend is tracking 6% under plan for the quarter.

Headcount notes:
- Two contractors converting to full-time in Q4, pending offer sign-off.
- On-call rotation coverage remains at 4 engineers; adding a fifth is under discussion.

Nothing here is time-sensitive, but this report is not meant to be broadly circulated.`

function generatePassword() {
  return crypto.randomBytes(9).toString('base64').replace(/[^a-zA-Z0-9]/g, '')
}

function seedDb(db) {
  const adminPassword = generatePassword()
  const { lastInsertRowid: adminId } = db
    .prepare('INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)')
    .run(ADMIN_USERNAME, ADMIN_EMAIL, adminPassword, 'admin')

  const { lastInsertRowid: reportId } = db
    .prepare('INSERT INTO reports (title, content) VALUES (?, ?)')
    .run(REPORT_TITLE, REPORT_CONTENT)

  return { adminId, adminPassword, reportId }
}

function initDb(dbPath) {
  const db = new Database(dbPath)
  db.pragma('journal_mode = WAL')
  db.exec(SCHEMA)
  const seed = seedDb(db)
  return { db, seed }
}

function resetDb(db) {
  db.exec('DELETE FROM scoring_events')
  db.exec('DELETE FROM reports')
  db.exec('DELETE FROM users')
  return seedDb(db)
}

function getDb(req) {
  return req.app.locals.db
}

module.exports = { initDb, seedDb, resetDb, getDb, ADMIN_EMAIL, ADMIN_USERNAME }
