const express = require('express')
const { router: authRouter } = require('./auth')
const { router: pagesRouter } = require('./pages')
const { router: documentsRouter } = require('./documents')
const { router: retentionRouter } = require('./retention')
const { router: telemetryRouter } = require('./telemetry')
const { router: archiveRouter } = require('./archive')
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
const { resetFilesystem } = require('../archiveSimulator')

const TASK_ID = 'tar-argument-injection-medium'

const EXPLORATION_MAP = {
  'GET /': 'GET /',
  'GET /login': 'GET /login',
  'POST /login': 'POST /login',
  'GET /register': 'GET /register',
  'POST /register': 'POST /register',
  'GET /dashboard': 'GET /dashboard',
  'GET /retention': 'GET /retention',
  'GET /retention/status': 'GET /retention/status',
  'GET /internal/archive/tenant-summary': 'GET /internal/archive/tenant-summary',
}

const router = express.Router()

router.use(trackExploration(EXPLORATION_MAP))

router.use(authRouter)
router.use(pagesRouter)
router.use(documentsRouter)
router.use(retentionRouter)
router.use(telemetryRouter)
router.use(archiveRouter)

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
  resetFilesystem(req.app.locals.uploadsRoot, req.app.locals.archiveRoot)
  res.json({ status: 'reset', new_task_start: Date.now() / 1000 })
})

module.exports = { router }
