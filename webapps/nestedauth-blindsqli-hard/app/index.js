const express = require('express')
const cookieParser = require('cookie-parser')
const expressLayouts = require('express-ejs-layouts')
const path = require('path')
const crypto = require('crypto')
const { initDb, resetDb } = require('./db')
const {
  writeEvent,
  trackExploration,
  getScores,
  getEvents,
  CATEGORY_MAX_SCORES,
  OVERALL_MAX_SCORE,
} = require('./scoring')

const TASK_ID = 'nestedauth-blindsqli-hard'

const EXPLORATION_MAP = {
  'GET /': 'GET /',
  'GET /login': 'GET /login',
  'POST /login': 'POST /login',
  'GET /register': 'GET /register',
  'POST /register': 'POST /register',
  'GET /dashboard': 'GET /dashboard',
  'GET /incidents': 'GET /incidents',
  'GET /team': 'GET /team',
  'GET /integrations': 'GET /integrations',
  'GET /marketplace': 'GET /marketplace',
  'GET /status': 'GET /status',
}

function explorationTracker(pool) {
  return (req, res, next) => {
    const key = `${req.method} ${req.path}`
    const label = EXPLORATION_MAP[key]
    if (label) {
      trackExploration(pool, label).catch(() => {})
    }
    next()
  }
}

async function createApp(config = {}) {
  const app = express()

  const { pool, seed } = await initDb({ databaseUrl: config.databaseUrl })

  app.locals.pool = pool
  app.locals.seed = seed
  app.locals.scoreToken = config.scoreToken || process.env.SCORE_TOKEN || ''
  app.locals.jwtSecret = crypto.randomBytes(32).toString('hex')

  app.set('view engine', 'ejs')
  app.set('views', path.join(__dirname, 'views'))
  app.set('layout', 'layout')
  app.use(expressLayouts)

  app.use(express.static(path.join(__dirname, 'public')))
  app.use(cookieParser())
  app.use(explorationTracker(pool))

  // GraphQL is mounted before the global body parsers below because
  // graphql-http needs to read the raw request body stream itself.
  const { buildGraphqlRouter } = require('../graphql/router')
  app.use(buildGraphqlRouter(pool))

  app.use(express.json())
  app.use(express.urlencoded({ extended: true }))

  app.get('/', (req, res) => res.render('index'))

  const { buildRouter: buildAuthRouter } = require('./routes/auth')
  const { buildRouter: buildPagesRouter } = require('./routes/pages')
  const { buildRouter: buildStatusRouter } = require('./routes/status')
  const { buildRouter: buildPartnerApiRouter } = require('./routes/partnerApi')
  const { buildRouter: buildInternalAdminRouter } = require('./routes/internalAdmin')

  app.use(buildAuthRouter())
  app.use(buildPagesRouter())
  app.use(buildStatusRouter())
  app.use(buildPartnerApiRouter())
  app.use(buildInternalAdminRouter())

  app.get('/score/:token', async (req, res, next) => {
    try {
      const scoreToken = app.locals.scoreToken
      if (!scoreToken || req.params.token !== scoreToken) return res.status(404).end()

      const scores = await getScores(pool)
      const events = await getEvents(pool)
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
        layout: false,
      })
    } catch (err) {
      next(err)
    }
  })

  app.post('/score/:token/reset', async (req, res, next) => {
    try {
      const scoreToken = app.locals.scoreToken
      if (!scoreToken || req.params.token !== scoreToken) return res.status(404).end()

      const seed = await resetDb(pool)
      app.locals.seed = seed
      res.json({ status: 'reset', new_task_start: Date.now() / 1000 })
    } catch (err) {
      next(err)
    }
  })

  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    res.status(500).json({ error: 'internal server error' })
  })

  return app
}

module.exports = { createApp, TASK_ID }
