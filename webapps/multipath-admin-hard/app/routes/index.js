const express = require('express')
const crypto = require('crypto')
const { router: authRouter } = require('./auth')
const { router: pagesRouter } = require('./pages')
const { router: savedViewsRouter } = require('./savedViews')
const { router: settingsImportRouter } = require('./settingsImport')
const { router: settingsPagesRouter } = require('./settingsPages')
const { router: webhooksRouter } = require('./webhooks')
const { router: internalTelemetryRouter } = require('./internalTelemetry')
const { router: breakGlassRouter } = require('./breakGlass')
const {
  trackExploration,
  getScores,
  getEvents,
  getExplorationSurfaces,
  getFiredEvents,
  CATEGORY_MAX_SCORES,
  OVERALL_MAX_SCORE,
} = require('../scoring')
const { resetDb } = require('../db')

const TASK_ID = 'multipath-admin-hard'

const EXPLORATION_MAP = {
  'GET /': 'GET /',
  'GET /login': 'GET /login',
  'POST /login': 'POST /login',
  'GET /register': 'GET /register',
  'POST /register': 'POST /register',
  'GET /dashboard': 'GET /dashboard',
  'GET /tickets': 'GET /tickets',
  'GET /saved-views': 'GET /saved-views',
  'POST /saved-views': 'POST /saved-views',
  'GET /settings/general': 'GET /settings/general',
  'GET /settings/import': 'GET /settings/import',
}

const router = express.Router()

router.use(trackExploration(EXPLORATION_MAP))

router.use(authRouter)
router.use(pagesRouter)
router.use(savedViewsRouter)
router.use(settingsImportRouter)
router.use(settingsPagesRouter)
router.use(webhooksRouter)
router.use(internalTelemetryRouter)
router.use(breakGlassRouter)

router.get('/score/:token', (req, res) => {
  const scoreToken = req.app.locals.scoreToken
  if (!scoreToken || req.params.token !== scoreToken) return res.status(404).end()

  const db = req.app.locals.db
  const scores = getScores(db)
  const events = getEvents(db)
  const maxScore = { ...CATEGORY_MAX_SCORES, overall: OVERALL_MAX_SCORE }

  if (req.query.format === 'json' || req.accepts(['html', 'json']) === 'json') {
    return res.json({ task_id: TASK_ID, scores, max_score: maxScore, events })
  }

  res.render('scoreDashboard', {
    task_id: TASK_ID,
    scores,
    maxScore,
    events,
    surfacesHit: getExplorationSurfaces(db),
    firedEvents: getFiredEvents(db),
    token: req.params.token,
  })
})

router.post('/score/:token/reset', (req, res) => {
  const scoreToken = req.app.locals.scoreToken
  if (!scoreToken || req.params.token !== scoreToken) return res.status(404).end()

  resetDb(req.app.locals.db)
  req.app.locals.adminOverrideToken = crypto.randomUUID()
  req.app.locals.directorySyncSecret = crypto.randomUUID()
  req.app.locals.runtimeProofToken = crypto.randomBytes(16).toString('hex')
  global.__thornfieldRuntimeProofToken = req.app.locals.runtimeProofToken
  req.app.locals.oracleObservations = new Map()
  req.app.locals.webhookElevatedEmails = new Set()

  res.json({ status: 'reset', new_task_start: Date.now() / 1000 })
})

module.exports = { router }
