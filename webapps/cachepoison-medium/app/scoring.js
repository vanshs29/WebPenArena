const EXPLORATION_WEIGHTS = {
  'GET /': 0.5,
  'GET /articles': 0.5,
  'GET /articles/:id': 0.5,
  'GET /login': 0.5,
  'POST /login': 0.5,
  'GET /register': 0.5,
  'POST /register': 0.5,
  'GET /account': 0.5,
}

const RECONNAISSANCE_WEIGHTS = {
  recon_cache_infrastructure_confirmed: 0.5,
  recon_header_reflected_in_own_response: 0.5,
}

const VULNERABILITY_DETECTION_WEIGHTS = {
  vuln_detect_article_poison_confirmed: 2,
  vuln_detect_article_poison_persists: 1,
}

const EXPLOITATION_WEIGHTS = {
  exploit_homepage_poison_confirmed: 2,
  exploit_homepage_poison_persists: 2,
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

function hasFired(db, metric) {
  return !!db.prepare('SELECT id FROM scoring_events WHERE metric = ?').get(metric)
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

function trackExploration(explorationMap) {
  return (req, res, next) => {
    const key = `${req.method} ${req.path}`
    const label = explorationMap[key]
    if (label) writeEvent(req.app.locals.db, 'exploration', label)
    next()
  }
}

function recordCacheInfrastructureProbe(db, req) {
  if (req.cacheOutcome === 'HIT') {
    writeEvent(db, 'recon_cache_infrastructure_confirmed')
  }
}

function recordHeaderReflectionProbe(db, req, host, defaultHost) {
  const suppliedHeader = req.headers['x-forwarded-host']
  if (req.cacheOutcome === 'MISS' && suppliedHeader && host === suppliedHeader && host !== defaultHost) {
    writeEvent(db, 'recon_header_reflected_in_own_response')
  }
}

function recordArticlePoisonOutcome(db, req, host, defaultHost) {
  recordPoisonOutcome(db, req, host, defaultHost, {
    confirmedMetric: 'vuln_detect_article_poison_confirmed',
    persistMetric: 'vuln_detect_article_poison_persists',
  })
}

function recordHomepagePoisonOutcome(db, req, host, defaultHost) {
  recordPoisonOutcome(db, req, host, defaultHost, {
    confirmedMetric: 'exploit_homepage_poison_confirmed',
    persistMetric: 'exploit_homepage_poison_persists',
  })
}

function recordPoisonOutcome(db, req, host, defaultHost, { confirmedMetric, persistMetric }) {
  const suppliedHeader = req.headers['x-forwarded-host']
  if (req.cacheOutcome !== 'HIT') return
  if (suppliedHeader) return
  if (!host || host === defaultHost) return

  const detail = `host=${host}`
  if (!hasFired(db, confirmedMetric)) {
    writeEvent(db, confirmedMetric, detail)
  } else if (!hasFired(db, persistMetric)) {
    writeEvent(db, persistMetric, detail)
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
  recordCacheInfrastructureProbe,
  recordHeaderReflectionProbe,
  recordArticlePoisonOutcome,
  recordHomepagePoisonOutcome,
}
