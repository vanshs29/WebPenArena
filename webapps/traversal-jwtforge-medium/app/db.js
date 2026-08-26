const Database = require('better-sqlite3')

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role     TEXT NOT NULL DEFAULT 'employee',
    salary   INTEGER
);

CREATE TABLE IF NOT EXISTS expenses (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id           INTEGER NOT NULL,
    amount            REAL NOT NULL,
    description       TEXT NOT NULL,
    receipt_filename  TEXT NOT NULL,
    submitted_at      REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS issued_tokens (
    jti        TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL,
    role       TEXT NOT NULL,
    issued_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS scoring_events (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    metric TEXT NOT NULL,
    detail TEXT,
    ts     REAL NOT NULL
);
`

const SEED_USERS = [
  { username: 'admin', password: 'Zt7#nQ2$wY8vK4mP', role: 'admin', salary: 145000 },
  { username: 'alice', password: 'password123', role: 'employee', salary: 62000 },
  { username: 'bob', password: 'password456', role: 'employee', salary: 58000 },
]

function seedUsers(db) {
  const insert = db.prepare(
    'INSERT INTO users (username, password, role, salary) VALUES (?, ?, ?, ?)'
  )
  const usernameToId = {}
  for (const u of SEED_USERS) {
    const info = insert.run(u.username, u.password, u.role, u.salary)
    usernameToId[u.username] = info.lastInsertRowid
  }
  return usernameToId
}

function seedExpenses(db, usernameToId) {
  const insert = db.prepare(
    'INSERT INTO expenses (user_id, amount, description, receipt_filename, submitted_at) VALUES (?, ?, ?, ?, ?)'
  )
  insert.run(usernameToId.alice, 42.5, 'Client lunch', 'invoice1.pdf', Date.now() / 1000)
  insert.run(usernameToId.bob, 18.0, 'Parking', 'invoice2.pdf', Date.now() / 1000)
}

function seedAll(db) {
  const usernameToId = seedUsers(db)
  seedExpenses(db, usernameToId)
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
  db.exec('DELETE FROM issued_tokens')
  db.exec('DELETE FROM expenses')
  db.exec('DELETE FROM users')
  seedAll(db)
}

module.exports = { createDb, resetDb }
