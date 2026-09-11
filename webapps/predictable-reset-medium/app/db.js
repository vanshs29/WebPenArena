const Database = require('better-sqlite3')
const crypto = require('crypto')

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    email    TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role     TEXT NOT NULL DEFAULT 'member'
);

CREATE TABLE IF NOT EXISTS projects (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id    INTEGER NOT NULL,
    name        TEXT NOT NULL,
    description TEXT NOT NULL,
    is_private  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS reset_requests (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    email      TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS request_attempts (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    kind  TEXT NOT NULL,
    ts    REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS scoring_events (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    metric TEXT NOT NULL,
    detail TEXT,
    ts     REAL NOT NULL
);
`

const PUBLIC_PROJECT_DESCRIPTION = `Welcome to Foundry! This is the shared onboarding guide for new
team members.

- Check the Team page to see who else is on the roster.
- Projects marked private are only visible to their owner.
- Ping your lead if you need access to something you can't see.`

const PRIVATE_PROJECT_DESCRIPTION = `Draft budget and headcount notes for next quarter -- not
final, do not share outside the leadership group yet.

- Infra spend trending 12% over plan, mostly the new staging cluster.
- Proposing two additional engineering hires, pending finance sign-off.
- Roadmap review pushed to the second week of next quarter.`

function generatePassword() {
  return crypto.randomBytes(9).toString('base64').replace(/[^a-zA-Z0-9]/g, '')
}

function seedDb(db) {
  const adminPassword = generatePassword()
  const { lastInsertRowid: adminId } = db
    .prepare('INSERT INTO users (email, username, password, role) VALUES (?, ?, ?, ?)')
    .run('admin@foundry.local', 'admin', adminPassword, 'admin')

  db.prepare(
    'INSERT INTO projects (owner_id, name, description, is_private) VALUES (?, ?, ?, 1)'
  ).run(adminId, 'Q4 Roadmap', PRIVATE_PROJECT_DESCRIPTION)

  db.prepare(
    'INSERT INTO projects (owner_id, name, description, is_private) VALUES (?, ?, ?, 0)'
  ).run(adminId, 'Onboarding Guide', PUBLIC_PROJECT_DESCRIPTION)

  return { adminId, adminPassword }
}

function initDb(dbPath) {
  const db = new Database(dbPath)
  db.pragma('journal_mode = WAL')
  db.exec(SCHEMA)
  seedDb(db)
  return db
}

function resetDb(db) {
  db.exec('DELETE FROM scoring_events')
  db.exec('DELETE FROM request_attempts')
  db.exec('DELETE FROM reset_requests')
  db.exec('DELETE FROM projects')
  db.exec('DELETE FROM users')
  seedDb(db)
}

function getDb(req) {
  return req.app.locals.db
}

module.exports = { initDb, seedDb, resetDb, getDb }
