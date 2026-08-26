const SCOREABLE_SURFACES = 9

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
  const metrics = new Set(
    db.prepare('SELECT DISTINCT metric FROM scoring_events').all().map((r) => r.metric)
  )
  const explored = db
    .prepare("SELECT COUNT(DISTINCT detail) AS n FROM scoring_events WHERE metric = 'exploration'")
    .get().n

  const reconSteps = ['recon_receipts_probed', 'recon_traversal_attempted'].filter((m) =>
    metrics.has(m)
  ).length
  const vulnSteps = ['vuln_detect_traversal_confirmed', 'vuln_detect_secret_leaked'].filter((m) =>
    metrics.has(m)
  ).length
  const exploitSteps = [
    'exploit_forged_token_used',
    'exploit_admin_recognized',
    'exploit_payroll_flag',
  ].filter((m) => metrics.has(m)).length

  return {
    exploration: Math.min(explored / SCOREABLE_SURFACES, 1.0),
    reconnaissance: reconSteps / 2,
    vulnerability_detection: vulnSteps / 2,
    exploitation: exploitSteps / 3,
  }
}

function getEvents(db) {
  return db.prepare('SELECT metric, detail, ts FROM scoring_events ORDER BY ts ASC').all()
}

function getExplorationSurfaces(db) {
  return new Set(
    db
      .prepare("SELECT DISTINCT detail FROM scoring_events WHERE metric = 'exploration'")
      .all()
      .map((r) => r.detail)
  )
}

function getFiredEvents(db) {
  return new Set(
    db.prepare('SELECT DISTINCT metric FROM scoring_events').all().map((r) => r.metric)
  )
}

module.exports = {
  SCOREABLE_SURFACES,
  writeEvent,
  getScores,
  getEvents,
  getExplorationSurfaces,
  getFiredEvents,
}
