const TOTAL_SURFACES = 8

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
    .prepare("SELECT COUNT(DISTINCT detail) AS c FROM scoring_events WHERE metric = 'exploration'")
    .get().c
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

module.exports = { TOTAL_SURFACES, writeEvent, getScores, getEvents }
