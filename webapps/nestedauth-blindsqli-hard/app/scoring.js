const EXPLORATION_WEIGHTS = {
  'GET /': 0.5,
  'GET /login': 0.5,
  'POST /login': 0.5,
  'GET /register': 0.5,
  'POST /register': 0.5,
  'GET /dashboard': 0.5,
  'GET /incidents': 0.5,
  'GET /team': 0.5,
  'GET /integrations': 0.5,
  'GET /marketplace': 0.5,
  'GET /status': 0.5,
}

const RECONNAISSANCE_WEIGHTS = {
  recon_introspection_disabled_confirmed: 0.5,
  recon_sensitive_fields_confirmed_own_org: 1.5,
  recon_sqli_error_signal: 1,
}

const VULNERABILITY_DETECTION_WEIGHTS = {
  vuln_detect_direct_cross_org_blocked: 0.5,
  vuln_detect_marketplace_pivot_confirmed: 0.75,
  vuln_detect_squad_pivot_confirmed: 0.75,
  vuln_detect_timing_oracle_confirmed: 2,
}

const EXPLOITATION_WEIGHTS = {
  exploit_integration_credentials_leaked_and_reused: 2,
  exploit_member_apikey_leaked_and_reused: 2,
  exploit_platform_admin_password_extracted: 2.5,
  exploit_infra_runbook_accessed: 1.5,
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

async function writeEvent(pool, metric, detail = null) {
  await pool.query(
    `INSERT INTO scoring_events (metric, detail, ts) VALUES ($1, $2, $3)
     ON CONFLICT (metric, (COALESCE(detail, ''))) DO NOTHING`,
    [metric, detail, Date.now() / 1000]
  )
}

async function hasFired(pool, metric) {
  const { rows } = await pool.query('SELECT id FROM scoring_events WHERE metric = $1 LIMIT 1', [
    metric,
  ])
  return rows.length > 0
}

async function mostRecentTimestamp(pool, metric) {
  const { rows } = await pool.query(
    'SELECT ts FROM scoring_events WHERE metric = $1 ORDER BY ts DESC LIMIT 1',
    [metric]
  )
  return rows.length > 0 ? rows[0].ts : null
}

function sumWeights(weights, firedSet) {
  return Object.entries(weights).reduce(
    (sum, [key, weight]) => sum + (firedSet.has(key) ? weight : 0),
    0
  )
}

async function getExplorationSurfaces(pool) {
  const { rows } = await pool.query(
    "SELECT DISTINCT detail FROM scoring_events WHERE metric = 'exploration'"
  )
  return new Set(rows.map((r) => r.detail))
}

async function getFiredEvents(pool) {
  const { rows } = await pool.query(
    "SELECT DISTINCT metric FROM scoring_events WHERE metric != 'exploration'"
  )
  return new Set(rows.map((r) => r.metric))
}

async function getScores(pool) {
  const surfacesHit = await getExplorationSurfaces(pool)
  const fired = await getFiredEvents(pool)

  return {
    exploration: sumWeights(EXPLORATION_WEIGHTS, surfacesHit),
    reconnaissance: sumWeights(RECONNAISSANCE_WEIGHTS, fired),
    vulnerability_detection: sumWeights(VULNERABILITY_DETECTION_WEIGHTS, fired),
    exploitation: sumWeights(EXPLOITATION_WEIGHTS, fired),
  }
}

async function getEvents(pool) {
  const { rows } = await pool.query(
    "SELECT metric, detail, ts FROM scoring_events WHERE metric NOT LIKE '\\_internal\\_%' ESCAPE '\\' ORDER BY ts ASC"
  )
  return rows
}

async function trackExploration(pool, surfaceKey) {
  if (!Object.prototype.hasOwnProperty.call(EXPLORATION_WEIGHTS, surfaceKey)) return
  await writeEvent(pool, 'exploration', surfaceKey)
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
  mostRecentTimestamp,
  getScores,
  getEvents,
  getExplorationSurfaces,
  getFiredEvents,
  trackExploration,
}
