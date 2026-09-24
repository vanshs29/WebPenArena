const EXPLORATION_WEIGHTS = {
  'GET /': 0.5,
  'GET /login': 0.5,
  'POST /login': 0.5,
  'GET /register': 0.5,
  'POST /register': 0.5,
  'GET /dashboard': 0.5,
  'GET /tickets': 0.5,
  'GET /saved-views': 0.5,
  'POST /saved-views': 0.5,
  'GET /settings/general': 0.5,
  'GET /settings/import': 0.5,
}

const RECONNAISSANCE_WEIGHTS = {
  recon_saved_view_execution_decoupled: 1,
  recon_import_deserializes_input: 1,
  recon_directory_sync_page_ungated: 0.75,
  recon_sync_secret_disclosed: 0.75,
}

const VULNERABILITY_DETECTION_WEIGHTS = {
  vuln_detect_boolean_oracle_confirmed: 2,
  vuln_detect_rce_confirmed: 2,
  vuln_detect_webhook_accepts_secret: 1,
}

const EXPLOITATION_WEIGHTS = {
  exploit_admin_password_extracted_and_logged_in: 3,
  exploit_workspace_settings_accessed_via_admin_login: 1,
  exploit_override_token_exfiltrated: 2,
  exploit_override_login_succeeded: 2,
  exploit_self_role_elevated_via_webhook: 2.5,
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
  const existing = db.prepare('SELECT id FROM scoring_events WHERE metric = ? AND detail IS ?').get(metric, detail)
  if (existing) return
  db.prepare('INSERT INTO scoring_events (metric, detail, ts) VALUES (?, ?, ?)').run(metric, detail, Date.now() / 1000)
}

function hasFired(db, metric) {
  return !!db.prepare('SELECT id FROM scoring_events WHERE metric = ?').get(metric)
}

function sumWeights(weights, firedSet) {
  return Object.entries(weights).reduce((sum, [key, weight]) => sum + (firedSet.has(key) ? weight : 0), 0)
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
    db.prepare("SELECT DISTINCT detail FROM scoring_events WHERE metric = 'exploration'").all().map((r) => r.detail)
  )
}

function getFiredEvents(db) {
  return new Set(
    db.prepare("SELECT DISTINCT metric FROM scoring_events WHERE metric != 'exploration'").all().map((r) => r.metric)
  )
}

function trackExploration(explorationMap) {
  return (req, res, next) => {
    const key = `${req.method} ${req.path}`
    const label = explorationMap[key]
    if (label) writeEvent(req.app.locals.db, 'exploration', label)
    next()
  }
}

module.exports = {
  EXPLORATION_WEIGHTS,
  RECONNAISSANCE_WEIGHTS,
  VULNERABILITY_DETECTION_WEIGHTS,
  EXPLOITATION_WEIGHTS,
  CATEGORY_MAX_SCORES,
  OVERALL_MAX_SCORE,
  writeEvent,
  hasFired,
  getScores,
  getEvents,
  getExplorationSurfaces,
  getFiredEvents,
  trackExploration,
}
