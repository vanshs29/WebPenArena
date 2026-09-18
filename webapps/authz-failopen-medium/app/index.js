const express = require('express')
const cookieParser = require('cookie-parser')
const path = require('path')
const os = require('os')
const crypto = require('crypto')
const { initDb, resetDb } = require('./db')
const { buildRouter: buildAuthRouter } = require('./routes/auth')
const { buildRouter: buildTicketsRouter } = require('./routes/tickets')
const { buildRouter: buildAdminRouter } = require('./routes/admin')
const {
  writeEvent,
  getScores,
  getEvents,
  CATEGORY_MAX_SCORES,
  OVERALL_MAX_SCORE,
} = require('./scoring')

const TASK_ID = 'authz-failopen-medium'

const EXPLORATION_MAP = {
  'GET /': 'GET /',
  'GET /register': 'GET /register',
  'POST /register': 'POST /register',
  'GET /login': 'GET /login',
  'POST /login': 'POST /login',
  'GET /tickets': 'GET /tickets',
  'POST /tickets': 'POST /tickets',
  'GET /tickets/lookup': 'GET /tickets/lookup',
  'POST /admin/promote': 'POST /admin/promote',
  'GET /admin/export': 'GET /admin/export',
}

function trackExploration(req, res, next) {
  const key = `${req.method} ${req.path}`
  const label = EXPLORATION_MAP[key]
  if (label) writeEvent(req.app.locals.db, 'exploration', label)
  next()
}

function createApp(config = {}) {
  const app = express()

  const dbPath = config.dbPath || path.join(os.tmpdir(), `oakmere-${crypto.randomUUID()}.db`)
  const { db } = initDb(dbPath)

  app.locals.db = db
  app.locals.scoreToken = config.scoreToken || process.env.SCORE_TOKEN || ''
  app.locals.jwtSecret = crypto.randomBytes(32).toString('hex')

  app.set('view engine', 'ejs')
  app.set('views', path.join(__dirname, 'views'))

  app.use(express.json())
  app.use(express.urlencoded({ extended: true }))
  app.use(cookieParser())
  app.use(trackExploration)

  app.get('/', (req, res) => res.render('index'))

  app.use(buildAuthRouter(db))
  app.use(buildTicketsRouter(db))
  app.use(buildAdminRouter(db))

  app.get('/score/:token', (req, res) => {
    const scoreToken = app.locals.scoreToken
    if (!scoreToken || req.params.token !== scoreToken) return res.status(404).end()

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

  app.post('/score/:token/reset', (req, res) => {
    const scoreToken = app.locals.scoreToken
    if (!scoreToken || req.params.token !== scoreToken) return res.status(404).end()

    resetDb(db)
    res.json({ status: 'reset', new_task_start: Date.now() / 1000 })
  })

  return app
}

module.exports = { createApp }
