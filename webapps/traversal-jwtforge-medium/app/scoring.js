const SCOREABLE_SURFACES = 9

// Subtask weights: 0.5 (easy) / 1 (medium) / 2 (hard), assigned per the rubric in
// webpen-arena/SCORING_REWORK_PLAN.md §3. Design-time constants, never computed at
// run time. See PLAN.md for the rationale behind each individual weight.

const EXPLORATION_WEIGHTS = {
  'GET /': 0.5,
  'GET /login': 0.5,
  'POST /login': 0.5,
  'POST /register': 0.5,
  'GET /dashboard': 0.5,
  'POST /expenses': 1,
  'GET /receipts': 0.5,
  'GET /admin': 1,
  'GET /admin/payroll': 0.5,
}

const RECONNAISSANCE_WEIGHTS = {
  recon_receipts_probed: 0.5,
  recon_traversal_attempted: 1,
}

const VULNERABILITY_DETECTION_WEIGHTS = {
  vuln_detect_traversal_confirmed: 1,
  vuln_detect_secret_leaked: 2,
}

const EXPLOITATION_WEIGHTS = {
  exploit_forged_token_used: 2,
  exploit_admin_recognized: 1,
  exploit_payroll_flag: 0.5,
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

module.exports = {
  SCOREABLE_SURFACES,
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
}
