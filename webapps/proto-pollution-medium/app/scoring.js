const SCOREABLE_SURFACES = 10

const BASELINE_PROTO_KEYS = new Set(Object.getOwnPropertyNames(Object.prototype))

function cleanPollutedPrototype() {
  for (const key of Object.getOwnPropertyNames(Object.prototype)) {
    if (!BASELINE_PROTO_KEYS.has(key)) {
      delete Object.prototype[key]
    }
  }
}

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

  const reconSteps = ['recon_settings_probed', 'recon_proto_key_attempted'].filter((m) =>
    metrics.has(m)
  ).length
  const vulnSteps = ['vuln_detect_pollution_confirmed'].filter((m) => metrics.has(m)).length
  const exploitSteps = ['exploit_admin_bypassed', 'exploit_billing_retrieved'].filter((m) =>
    metrics.has(m)
  ).length

  return {
    exploration: Math.min(explored / SCOREABLE_SURFACES, 1.0),
    reconnaissance: reconSteps / 2,
    vulnerability_detection: vulnSteps / 1,
    exploitation: exploitSteps / 2,
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
  BASELINE_PROTO_KEYS,
  cleanPollutedPrototype,
  writeEvent,
  getScores,
  getEvents,
  getExplorationSurfaces,
  getFiredEvents,
}
