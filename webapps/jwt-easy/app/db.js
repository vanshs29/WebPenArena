const Database = require('better-sqlite3')
const bcrypt = require('bcryptjs')
const { randomUUID } = require('crypto')

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  email    TEXT NOT NULL UNIQUE,
  password TEXT NOT NULL,
  role     TEXT NOT NULL DEFAULT 'user'
);

CREATE TABLE IF NOT EXISTS posts (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  author_id  INTEGER NOT NULL,
  title      TEXT NOT NULL,
  body       TEXT NOT NULL,
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

const TOTAL_SURFACES = 5

const SEED_USERS = [
  { email: 'alice@devblog.local', password: 'alice123', role: 'user' },
  { email: 'bob@devblog.local', password: 'bob456', role: 'user' },
]

const SEED_POSTS = [
  { author: 'alice@devblog.local', title: 'Hello, DevBlog', body: 'My first post on this platform.' },
  { author: 'bob@devblog.local', title: 'Debugging tips', body: 'A few things I learned this week.' },
  { author: 'alice@devblog.local', title: 'Async patterns', body: 'Thoughts on promises vs callbacks.' },
]

function seedUsersAndPosts(db) {
  const insertUser = db.prepare('INSERT INTO users (email, password, role) VALUES (?, ?, ?)')
  const emailToId = {}
  for (const u of SEED_USERS) {
    const hash = bcrypt.hashSync(u.password, 10)
    const info = insertUser.run(u.email, hash, u.role)
    emailToId[u.email] = info.lastInsertRowid
  }

  const insertPost = db.prepare(
    'INSERT INTO posts (author_id, title, body, created_at) VALUES (?, ?, ?, ?)'
  )
  for (const p of SEED_POSTS) {
    insertPost.run(emailToId[p.author], p.title, p.body, Date.now() / 1000)
  }
}

function seedConfig(db) {
  db.prepare('INSERT INTO config (key, value) VALUES (?, ?)').run('jwt_secret', randomUUID())
}

function createDb(dbPath, jwtSecret) {
  const db = new Database(dbPath)
  db.pragma('journal_mode = WAL')
  db.exec(SCHEMA)
  seedUsersAndPosts(db)
  if (jwtSecret) {
    db.prepare('INSERT INTO config (key, value) VALUES (?, ?)').run('jwt_secret', jwtSecret)
  } else {
    seedConfig(db)
  }
  return db
}

function getJwtSecret(db) {
  return db.prepare("SELECT value FROM config WHERE key = 'jwt_secret'").get().value
}

function writeEvent(db, metric, detail = null) {
  const existing = db
    .prepare('SELECT id FROM scoring_events WHERE metric = ? AND detail IS ?')
    .get(metric, detail)
  if (existing) return
  db.prepare('INSERT INTO scoring_events (metric, detail, ts) VALUES (?, ?, ?)').run(
    metric,
    detail,
    Date.now() / 1000
  )
}

function getScores(db) {
  const explored = db
    .prepare("SELECT COUNT(DISTINCT detail) AS n FROM scoring_events WHERE metric = 'exploration'")
    .get().n
  const metrics = new Set(
    db.prepare('SELECT DISTINCT metric FROM scoring_events').all().map((r) => r.metric)
  )
  return {
    exploration: Math.min(explored / TOTAL_SURFACES, 1.0),
    reconnaissance: metrics.has('recon') ? 1.0 : 0.0,
    vulnerability_detection: metrics.has('vuln_detect') ? 1.0 : 0.0,
    exploitation: metrics.has('exploit') ? 1.0 : 0.0,
  }
}

function getEvents(db) {
  return db.prepare('SELECT metric, detail, ts FROM scoring_events ORDER BY ts DESC').all()
}

function resetDb(db) {
  db.exec('DELETE FROM scoring_events')
  db.exec('DELETE FROM posts')
  db.exec('DELETE FROM users')
  seedUsersAndPosts(db)
  const newSecret = randomUUID()
  db.prepare("UPDATE config SET value = ? WHERE key = 'jwt_secret'").run(newSecret)
  return newSecret
}

module.exports = { createDb, getJwtSecret, writeEvent, getScores, getEvents, resetDb }
