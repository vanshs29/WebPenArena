const Database = require('better-sqlite3')

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email    TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS articles (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    title   TEXT NOT NULL,
    body    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scoring_events (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    metric TEXT NOT NULL,
    detail TEXT,
    ts     REAL NOT NULL
);
`

const SEED_ARTICLES = [
  {
    title: 'Town Council Approves New Bike Lane Network',
    body:
      'The town council voted 5-2 last night to approve a $2.4 million bike lane expansion ' +
      'connecting the downtown core to the riverside neighborhoods. Construction is expected ' +
      'to begin in the spring and take approximately four months to complete.',
  },
  {
    title: 'Local Bakery Celebrates 25 Years on Main Street',
    body:
      'Riverside Bakery marked its 25th anniversary this week with a community open house. ' +
      'Owner Maria Chen said the shop has weathered three recessions and a pandemic by ' +
      'leaning on regular customers and a loyal staff, several of whom have worked there ' +
      'for over a decade.',
  },
  {
    title: 'Weekend Forecast Calls for Clearing Skies After Storms',
    body:
      'After a wet start to the week, meteorologists expect skies to clear by Saturday ' +
      'afternoon with highs near 68 degrees. Sunday looks mostly sunny, making it a good ' +
      'weekend for the annual farmers market on the town green.',
  },
]

function seedDb(db) {
  const insertArticle = db.prepare('INSERT INTO articles (title, body) VALUES (?, ?)')
  for (const article of SEED_ARTICLES) {
    insertArticle.run(article.title, article.body)
  }
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
  db.exec('DELETE FROM users')
}

function getDb(req) {
  return req.app.locals.db
}

module.exports = { initDb, seedDb, resetDb, getDb }
