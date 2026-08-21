const Database = require('better-sqlite3')
const bcrypt = require('bcryptjs')
const { randomUUID } = require('crypto')

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id                   INTEGER PRIMARY KEY AUTOINCREMENT,
  email                TEXT UNIQUE NOT NULL,
  password_hash        TEXT NOT NULL,
  subscription_active  INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS pages (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_id   INTEGER NOT NULL,
  html       TEXT NOT NULL,
  created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS reports (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  url        TEXT NOT NULL,
  reviewed   INTEGER NOT NULL DEFAULT 0,
  created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS scoring_events (
  id     INTEGER PRIMARY KEY AUTOINCREMENT,
  metric TEXT NOT NULL,
  detail TEXT,
  ts     REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS config (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
`

const VICTIM_EMAIL = 'victim@billfold.local'
const VICTIM_PASSWORD = 'B1llf0ld-Victim!'

function seedVictim(db) {
  const hash = bcrypt.hashSync(VICTIM_PASSWORD, 10)
  db.prepare(
    'INSERT INTO users (email, password_hash, subscription_active) VALUES (?, ?, 1)'
  ).run(VICTIM_EMAIL, hash)
}

function createDb(dbPath, jwtSecret) {
  const db = new Database(dbPath)
  db.pragma('journal_mode = WAL')
  db.exec(SCHEMA)
  seedVictim(db)
  db.prepare('INSERT INTO config (key, value) VALUES (?, ?)').run(
    'jwt_secret',
    jwtSecret || randomUUID()
  )
  return db
}

function getJwtSecret(db) {
  return db.prepare("SELECT value FROM config WHERE key = 'jwt_secret'").get().value
}

function resetDb(db) {
  db.exec('DELETE FROM scoring_events')
  db.exec('DELETE FROM reports')
  db.exec('DELETE FROM pages')
  db.prepare('UPDATE users SET subscription_active = 1 WHERE email = ?').run(VICTIM_EMAIL)
}

module.exports = { SCHEMA, VICTIM_EMAIL, VICTIM_PASSWORD, createDb, getJwtSecret, resetDb }
