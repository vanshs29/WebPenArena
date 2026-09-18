const express = require('express')
const { router: authRouter } = require('./auth')
const { router: pagesRouter } = require('./pages')
const { router: statusRouter } = require('./status')
const { router: billingRouter } = require('./billing')
const { writeEvent, getScores, getEvents, CATEGORY_MAX_SCORES, OVERALL_MAX_SCORE } = require('../scoring')
const { resetDb: resetAppDb } = require('../db')
const { resetDb: resetRegistryDb } = require('../registry/db')

const TASK_ID = 'dependency-confusion-medium'

const EXPLORATION_MAP = {
  'GET /': 'GET /',
  'GET /login': 'GET /login',
  'POST /login': 'POST /login',
  'GET /register': 'GET /register',
  'POST /register': 'POST /register',
  'GET /dashboard': 'GET /dashboard',
  'GET /status': 'GET /status',
  'GET /status/build-info': 'GET /status/build-info',
}

function trackExploration(req, res, next) {
  const key = `${req.method} ${req.path}`
  const label = EXPLORATION_MAP[key]
  if (label) writeEvent(req.app.locals.db, 'exploration', label)
  next()
}

const router = express.Router()

router.use(trackExploration)

router.use(authRouter)
router.use(pagesRouter)
router.use(statusRouter)
router.use(billingRouter)

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
    token: req.params.token,
  })
})

router.post('/score/:token/reset', (req, res) => {
  const scoreToken = req.app.locals.scoreToken
  if (!scoreToken || req.params.token !== scoreToken) return res.status(404).end()

  resetAppDb(req.app.locals.db)
  resetRegistryDb(req.app.locals.registryDb)
  res.json({ status: 'reset', new_task_start: Date.now() / 1000 })
})

module.exports = { router }
