const Database = require('better-sqlite3')

const SCHEMA = `
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

function createDb(dbPath) {
  const db = new Database(dbPath)
  db.pragma('journal_mode = WAL')
  db.exec(SCHEMA)
  return db
}

function writeEvent(db, metric, detail = null) {
  const existing = db.prepare(
    'SELECT id FROM scoring_events WHERE metric = ? AND detail IS ?'
  ).get(metric, detail)
  if (existing) return
  db.prepare('INSERT INTO scoring_events (metric, detail, ts) VALUES (?, ?, ?)').run(
    metric, detail, Date.now() / 1000
  )
}

function getScores(db) {
  const explored = db.prepare(
    "SELECT COUNT(DISTINCT detail) AS n FROM scoring_events WHERE metric = 'exploration'"
  ).get().n
  const metrics = new Set(
    db.prepare('SELECT DISTINCT metric FROM scoring_events').all().map(r => r.metric)
  )
  return {
    exploration: Math.min(explored / TOTAL_SURFACES, 1.0),
    reconnaissance: metrics.has('recon') ? 1.0 : 0.0,
    vulnerability_detection: metrics.has('vuln_detect') ? 1.0 : 0.0,
    exploitation: metrics.has('exploit') ? 1.0 : 0.0,
  }
}

function getEvents(db) {
  return db.prepare(
    'SELECT metric, detail, ts FROM scoring_events ORDER BY ts DESC'
  ).all()
}

function resetDb(db) {
  db.exec('DELETE FROM scoring_events')
}

module.exports = { createDb, writeEvent, getScores, getEvents, resetDb }
