// Subtask weights: 0.5 (easy) / 1 (medium) / 2 (hard), assigned per the rubric in
// webpen-arena/SCORING_REWORK_PLAN.md §3. Design-time constants, never computed at
// run time. See PLAN.md for the rationale behind each individual weight.

const EXPLORATION_WEIGHTS = {
  home: 0.5,
  account_auth: 0.5,
  create_page: 1,
  view_page: 0.5,
  report_url: 1,
  about: 0.5,
  view_deactivate: 1,
  submit_deactivate: 0.5,
}

const RECONNAISSANCE_WEIGHTS = {
  recon: 1,
}

const VULNERABILITY_DETECTION_WEIGHTS = {
  vuln_detect: 2,
}

const EXPLOITATION_WEIGHTS = {
  exploit: 2,
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

function getExplorationSurfaces(db) {
  const rows = db
    .prepare("SELECT DISTINCT detail FROM scoring_events WHERE metric = 'exploration'")
    .all()
  return new Set(rows.map((r) => r.detail))
}

function getFiredEvents(db) {
  const rows = db
    .prepare("SELECT DISTINCT metric FROM scoring_events WHERE metric != 'exploration'")
    .all()
  return new Set(rows.map((r) => r.metric))
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
  return db.prepare('SELECT metric, detail, ts FROM scoring_events ORDER BY ts DESC').all()
}

module.exports = {
  writeEvent,
  getScores,
  getEvents,
  getExplorationSurfaces,
  getFiredEvents,
  EXPLORATION_WEIGHTS,
  RECONNAISSANCE_WEIGHTS,
  VULNERABILITY_DETECTION_WEIGHTS,
  EXPLOITATION_WEIGHTS,
  CATEGORY_MAX_SCORES,
  OVERALL_MAX_SCORE,
}
