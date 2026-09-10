const Database = require('better-sqlite3')

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role     TEXT NOT NULL DEFAULT 'member'
);

CREATE TABLE IF NOT EXISTS feed_posts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    message     TEXT NOT NULL,
    posted_at   REAL NOT NULL
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
  { username: 'admin', password: 'Kp9#vR3$mL7xQ2w', role: 'admin' },
  { username: 'alice', password: 'password123', role: 'member' },
  { username: 'bob', password: 'password456', role: 'member' },
]

function seedUsers(db) {
  const insert = db.prepare('INSERT INTO users (username, password, role) VALUES (?, ?, ?)')
  const usernameToId = {}
  for (const u of SEED_USERS) {
    const info = insert.run(u.username, u.password, u.role)
    usernameToId[u.username] = info.lastInsertRowid
  }
  return usernameToId
}

function seedFeedPosts(db, usernameToId) {
  const insert = db.prepare(
    'INSERT INTO feed_posts (user_id, message, posted_at) VALUES (?, ?, ?)'
  )
  const now = Date.now() / 1000
  insert.run(usernameToId.alice, 'heading to lunch, back in 30', now - 3600)
  insert.run(usernameToId.bob, 'pushed the release notes to the wiki', now - 1800)
  insert.run(usernameToId.alice, 'does anyone have the Q3 deck?', now - 600)
}

function seedAll(db) {
  const usernameToId = seedUsers(db)
  seedFeedPosts(db, usernameToId)
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
  db.exec('DELETE FROM feed_posts')
  db.exec('DELETE FROM users')
  seedAll(db)
}

module.exports = { createDb, resetDb }
