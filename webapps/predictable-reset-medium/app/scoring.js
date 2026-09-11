const EXPLORATION_WEIGHTS = {
  'GET /': 0.5,
  'GET /login': 0.5,
  'POST /login': 0.5,
  'GET /register': 0.5,
  'POST /register': 0.5,
  'GET /dashboard': 0.5,
  'GET /team': 0.5,
  'GET /projects/:id': 0.5,
  'GET /forgot-password': 0.5,
  'POST /forgot-password': 0.5,
  'GET /reset-password': 0.5,
  'POST /reset-password/confirm': 0.5,
}

const RECONNAISSANCE_WEIGHTS = {
  recon_reset_requested: 0.5,
  recon_bad_guess_rejected: 0.5,
  recon_rate_limit_observed: 0.5,
}

const VULNERABILITY_DETECTION_WEIGHTS = {
  vuln_detect_self_predicted_token: 2,
  vuln_detect_login_confirmed: 1,
}

const EXPLOITATION_WEIGHTS = {
  exploit_admin_password_reset: 2,
  exploit_login_as_admin: 1,
  exploit_private_project_accessed: 1,
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
