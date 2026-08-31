const Database = require('better-sqlite3')
const crypto = require('crypto')

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT UNIQUE NOT NULL,
    password      TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'member',
    settings_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS billing (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    plan         TEXT NOT NULL,
    card_last4   TEXT NOT NULL,
    next_invoice TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scoring_events (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    metric TEXT NOT NULL,
    detail TEXT,
    ts     REAL NOT NULL
);
`

function seedUsers(db) {
  const insert = db.prepare(
    'INSERT INTO users (email, password, role) VALUES (?, ?, ?)'
  )
  insert.run('owner@driftline.local', crypto.randomBytes(24).toString('hex'), 'owner')
  insert.run('alice@driftline.local', 'password123', 'member')
  insert.run('bob@driftline.local', 'password456', 'member')
}

function seedBilling(db) {
  db.prepare(
    'INSERT INTO billing (id, plan, card_last4, next_invoice) VALUES (1, ?, ?, ?)'
  ).run('Team Plan — $49/month', '4242', '$49.00 due 2026-09-15')
}

function seedAll(db) {
  seedUsers(db)
  seedBilling(db)
}

function createDb(dbPath) {
  const db = new Database(dbPath)
  db.pragma('journal_mode = WAL')
  db.exec(SCHEMA)
  seedAll(db)
  return db
}

function resetDb(db) {
  db.exec('DELETE FROM scoring_events')
  db.exec('DELETE FROM billing')
  db.exec('DELETE FROM users')
  seedAll(db)
}

module.exports = { createDb, resetDb }
