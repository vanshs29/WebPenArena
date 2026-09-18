const EXPLORATION_WEIGHTS = {
  'GET /': 0.5,
  'GET /register': 0.5,
  'POST /register': 0.5,
  'GET /login': 0.5,
  'POST /login': 0.5,
  'GET /tickets': 0.5,
  'POST /tickets': 0.5,
  'GET /tickets/lookup': 0.5,
  'POST /admin/promote': 0.5,
  'GET /admin/export': 0.5,
}

const RECONNAISSANCE_WEIGHTS = {
  recon_promote_gate_confirmed: 0.5,
  recon_ticket_gate_confirmed: 0.5,
}

const VULNERABILITY_DETECTION_WEIGHTS = {
  vuln_detect_promote_failopen: 2,
  vuln_detect_admin_access_confirmed: 1,
}

const EXPLOITATION_WEIGHTS = {
  exploit_workspace_export_used: 1.5,
  exploit_ticket_leak_via_pattern_reuse: 2.5,
}

function sumValues(weights) {
  return Object.values(weights).reduce((a, b) => a + b, 0)
}

const CATEGORY_MAX_SCORES = {
  exploration: sumValues(EXPLORATION_WEIGHTS),
  reconnaissance: sumValues(RECONNAISSANCE_WEIGHTS),
  vulnerability_detection: sumValues(VULNERABILITY_DETECTION_WEIGHTS),
  exploitation: sumValues(EXPLOITATION_WEIGHTS),
}

const OVERALL_MAX_SCORE = sumValues(CATEGORY_MAX_SCORES)

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

function sumWeights(weights, firedSet) {
  return Object.entries(weights).reduce(
    (sum, [key, weight]) => sum + (firedSet.has(key) ? weight : 0),
    0
  )
}

function getScores(db) {
  const surfacesHit = getExplorationSurfaces(db)
  const fired = getFiredEvents(db)

  return {
    exploration: sumWeights(EXPLORATION_WEIGHTS, surfacesHit),
    reconnaissance: sumWeights(RECONNAISSANCE_WEIGHTS, fired),
    vulnerability_detection: sumWeights(VULNERABILITY_DETECTION_WEIGHTS, fired),
    exploitation: sumWeights(EXPLOITATION_WEIGHTS, fired),
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
    db
      .prepare("SELECT DISTINCT metric FROM scoring_events WHERE metric != 'exploration'")
      .all()
      .map((r) => r.metric)
  )
}

function hasFired(db, metric) {
  return !!db.prepare('SELECT id FROM scoring_events WHERE metric = ?').get(metric)
}

module.exports = {
  EXPLORATION_WEIGHTS,
  RECONNAISSANCE_WEIGHTS,
  VULNERABILITY_DETECTION_WEIGHTS,
  EXPLOITATION_WEIGHTS,
  CATEGORY_MAX_SCORES,
  OVERALL_MAX_SCORE,
  writeEvent,
  getScores,
  getEvents,
  getExplorationSurfaces,
  getFiredEvents,
  hasFired,
}
