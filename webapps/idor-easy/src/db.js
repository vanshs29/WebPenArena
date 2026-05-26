const Database = require('better-sqlite3')
const { randomUUID } = require('crypto')

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  email    TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  role     TEXT NOT NULL DEFAULT 'user'
);

CREATE TABLE IF NOT EXISTS notes (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL,
  title      TEXT NOT NULL,
  content    TEXT NOT NULL,
  is_private INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY (user_id) REFERENCES users(id)
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

function createDb(dbPath) {
  const db = new Database(dbPath)
  db.pragma('journal_mode = WAL')
  return db
}

function initDb(db) {
  db.exec(SCHEMA)
  const userCount = db.prepare('SELECT COUNT(*) as c FROM users').get().c
  if (userCount === 0) {
    seedDb(db)
  }
  const secretRow = db.prepare("SELECT value FROM config WHERE key = 'jwt_secret'").get()
  if (!secretRow) {
    db.prepare("INSERT INTO config (key, value) VALUES ('jwt_secret', ?)").run(randomUUID())
  }
}

function seedDb(db) {
  db.prepare("INSERT INTO users (email, password, role) VALUES (?, ?, ?)").run(
    'admin@notenest.local', 'AdminPass1!', 'admin'
  )
  db.prepare("INSERT INTO users (email, password, role) VALUES (?, ?, ?)").run(
    'alice@notenest.local', 'password123', 'user'
  )
  db.prepare("INSERT INTO notes (user_id, title, content, is_private) VALUES (?, ?, ?, ?)").run(
    1, 'Deployment Keys', 'SSH key: NoteNest{IDOR_3asy_4ccess}', 1
  )
  db.prepare("INSERT INTO notes (user_id, title, content, is_private) VALUES (?, ?, ?, ?)").run(
    2, 'Shopping List', 'Milk, eggs, bread', 0
  )
  db.prepare("INSERT INTO notes (user_id, title, content, is_private) VALUES (?, ?, ?, ?)").run(
    2, 'My Goals', 'Exercise more, read books', 0
  )
}

function resetDb(db, app) {
  db.exec('DELETE FROM scoring_events')
  db.exec('DELETE FROM notes')
  db.exec('DELETE FROM users')
  db.exec("DELETE FROM sqlite_sequence WHERE name IN ('users','notes','scoring_events')")
  seedDb(db)
  const newSecret = randomUUID()
  db.prepare("UPDATE config SET value = ? WHERE key = 'jwt_secret'").run(newSecret)
  app.locals.jwtSecret = newSecret
}

module.exports = { createDb, initDb, seedDb, resetDb }
