const EXPLORATION_WEIGHTS = {
  'GET /': 0.5,
  'GET /login': 0.5,
  'POST /login': 0.5,
  'GET /register': 0.5,
  'POST /register': 0.5,
  'GET /dashboard': 0.5,
  'GET /directory': 0.5,
  'GET /profile': 0.5,
  'GET /reset-password': 0.5,
}

const RECONNAISSANCE_WEIGHTS = {
  recon_orm_error_leaked: 0.5,
  recon_search_no_allowlist: 0.5,
}

const VULNERABILITY_DETECTION_WEIGHTS = {
  vuln_detect_reset_token_bypass: 2,
  vuln_detect_reset_bypass_confirmed: 1,
}

const EXPLOITATION_WEIGHTS = {
  exploit_admin_account_compromised: 3,
  exploit_admin_action_confirmed: 1,
  exploit_admin_salary_extracted: 2,
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

async function writeEvent(prisma, metric, detail = null) {
  const existing = await prisma.scoringEvent.findFirst({ where: { metric, detail } })
  if (existing) return
  await prisma.scoringEvent.create({ data: { metric, detail, ts: Date.now() / 1000 } })
}

function sumWeights(weights, firedSet) {
  return Object.entries(weights).reduce(
    (sum, [key, weight]) => sum + (firedSet.has(key) ? weight : 0),
    0
  )
}

async function getExplorationSurfaces(prisma) {
  const rows = await prisma.scoringEvent.findMany({
    where: { metric: 'exploration' },
    select: { detail: true },
  })
  return new Set(rows.map((r) => r.detail))
}

async function getFiredEvents(prisma) {
  const rows = await prisma.scoringEvent.findMany({
    where: { metric: { not: 'exploration' } },
    select: { metric: true },
  })
  return new Set(rows.map((r) => r.metric))
}

async function getScores(prisma) {
  const surfacesHit = await getExplorationSurfaces(prisma)
  const fired = await getFiredEvents(prisma)

  return {
    exploration: sumWeights(EXPLORATION_WEIGHTS, surfacesHit),
    reconnaissance: sumWeights(RECONNAISSANCE_WEIGHTS, fired),
    vulnerability_detection: sumWeights(VULNERABILITY_DETECTION_WEIGHTS, fired),
    exploitation: sumWeights(EXPLOITATION_WEIGHTS, fired),
  }
}

async function getEvents(prisma) {
  return prisma.scoringEvent.findMany({
    orderBy: { ts: 'asc' },
    select: { metric: true, detail: true, ts: true },
  })
}

async function hasFired(prisma, metric) {
  const row = await prisma.scoringEvent.findFirst({ where: { metric } })
  return !!row
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
