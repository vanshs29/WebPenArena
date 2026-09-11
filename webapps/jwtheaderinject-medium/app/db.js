const Database = require('better-sqlite3')

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email    TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS orders (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    description TEXT NOT NULL,
    amount      REAL NOT NULL,
    status      TEXT NOT NULL DEFAULT 'paid'
);

CREATE TABLE IF NOT EXISTS partners (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    partner_id   TEXT UNIQUE NOT NULL,
    name         TEXT NOT NULL,
    access_level TEXT NOT NULL DEFAULT 'default'
);

CREATE TABLE IF NOT EXISTS customers (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    name  TEXT NOT NULL,
    email TEXT NOT NULL,
    plan  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS refunds (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    partner_id TEXT NOT NULL,
    order_id   INTEGER NOT NULL,
    amount     REAL NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS scoring_events (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    metric TEXT NOT NULL,
    detail TEXT,
    ts     REAL NOT NULL
);
`

const PARTNERS = [
  ['default-tier', 'Default Tier Partner', 'default'],
  ['acme-enterprise', 'Acme Enterprise', 'full'],
]

const CUSTOMERS = [
  ['Jordan Blake', 'jordan.blake@example.com', 'Pro'],
  ['Morgan Lee', 'morgan.lee@example.com', 'Starter'],
  ['Casey Kim', 'casey.kim@example.com', 'Enterprise'],
  ['Riley Chen', 'riley.chen@example.com', 'Pro'],
  ['Avery Patel', 'avery.patel@example.com', 'Starter'],
  ['Dakota Reyes', 'dakota.reyes@example.com', 'Enterprise'],
]

const STARTER_ORDER_DESCRIPTION = 'Starter Plan Subscription'
const STARTER_ORDER_AMOUNT = 49.0

function seedStaticData(db) {
  const insertPartner = db.prepare(
    'INSERT INTO partners (partner_id, name, access_level) VALUES (?, ?, ?)'
  )
  for (const partner of PARTNERS) insertPartner.run(...partner)

  const insertCustomer = db.prepare('INSERT INTO customers (name, email, plan) VALUES (?, ?, ?)')
  for (const customer of CUSTOMERS) insertCustomer.run(...customer)
}

function createOrderForUser(db, userId) {
  db.prepare(
    'INSERT INTO orders (user_id, description, amount, status) VALUES (?, ?, ?, ?)'
  ).run(userId, STARTER_ORDER_DESCRIPTION, STARTER_ORDER_AMOUNT, 'paid')
}

function initDb(dbPath) {
  const db = new Database(dbPath)
  db.pragma('journal_mode = WAL')
  db.exec(SCHEMA)
  seedStaticData(db)
  return db
}

function resetDb(db) {
  db.exec('DELETE FROM scoring_events')
  db.exec('DELETE FROM refunds')
  db.exec('DELETE FROM orders')
  db.exec('DELETE FROM users')
  db.exec('DELETE FROM customers')
  db.exec('DELETE FROM partners')
  seedStaticData(db)
}

function getDb(req) {
  return req.app.locals.db
}

module.exports = { initDb, resetDb, getDb, createOrderForUser }
