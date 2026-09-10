const express = require('express')
const jwt = require('jsonwebtoken')
const {
  writeEvent,
  getScores,
  getEvents,
  getExplorationSurfaces,
  getFiredEvents,
  CATEGORY_MAX_SCORES,
  OVERALL_MAX_SCORE,
} = require('./scoring')
const { issueToken, requireAuth, requireAdmin } = require('./auth')
const { resetDb } = require('./db')
const { generateKeypair, writeKeys } = require('./keys')
const { generateBillingArtifact } = require('./billing')

const TASK_ID = 'logforge-jwtconfusion-medium'

const EXPLORATION_MAP = {
  'GET /': 'GET /',
  'GET /login': 'GET /login',
  'POST /login': 'POST /login',
  'GET /register': 'GET /register',
  'POST /register': 'POST /register',
  'GET /dashboard': 'GET /dashboard',
  'GET /feed': 'GET /feed',
  'POST /feed': 'POST /feed',
  'GET /account/security': 'GET /account/security',
  'GET /keys/verify.pem': 'GET /keys/verify.pem',
  'GET /admin': 'GET /admin',
  'GET /admin/team': 'GET /admin/team',
  'GET /admin/billing': 'GET /admin/billing',
}

function trackExploration(req, res, next) {
  const db = req.app.locals.db
  const key = `${req.method} ${req.route ? req.baseUrl + req.route.path : req.path}`
  const label = EXPLORATION_MAP[key]
  if (label) writeEvent(db, 'exploration', label)
  next()
}

function formatTimestamp(unixSeconds) {
  return new Date(unixSeconds * 1000).toISOString().replace('T', ' ').slice(0, 19)
}

const router = express.Router()

router.get('/', trackExploration, (req, res) => {
  res.render('index')
})

router.get('/login', trackExploration, (req, res) => {
  res.render('login', { error: null })
})

router.post('/login', trackExploration, (req, res) => {
  const db = req.app.locals.db
  const { username, password } = req.body || {}
  if (!username || !password) {
    return res.status(401).json({ error: 'Invalid credentials' })
  }
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username)
  if (!user || user.password !== password) {
    return res.status(401).json({ error: 'Invalid credentials' })
  }
  const token = issueToken(req.app, user)
  res.cookie('session', token, { httpOnly: true })
  res.status(200).json({ message: 'Logged in' })
})

router.get('/register', trackExploration, (req, res) => {
  res.render('register', { error: null })
})

router.post('/register', trackExploration, (req, res) => {
  const db = req.app.locals.db
  const { username, password } = req.body || {}
  if (!username || !password) {
    return res.status(400).json({ error: 'username and password are required' })
  }
  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username)
  if (existing) {
    return res.status(409).json({ error: 'Username already taken' })
  }
  db.prepare('INSERT INTO users (username, password, role) VALUES (?, ?, ?)').run(
    username,
    password,
    'member'
  )
  res.status(201).json({ message: 'Registered' })
})

router.get('/dashboard', trackExploration, requireAuth, (req, res) => {
  res.render('dashboard')
})

router.get('/feed', trackExploration, requireAuth, (req, res) => {
  const db = req.app.locals.db
  const posts = db
    .prepare(
      `SELECT feed_posts.message, feed_posts.posted_at, users.username
       FROM feed_posts JOIN users ON users.id = feed_posts.user_id
       ORDER BY feed_posts.id`
    )
    .all()

  if (posts.length > 0) {
    writeEvent(db, 'recon_feed_format_observed', 'Feed viewed with existing content')
  }

  const entries = posts.map((post) => `[${formatTimestamp(post.posted_at)}] [${post.username}] ${post.message}`)
  const lines = entries.flatMap((entry) => entry.split('\n'))

  if (lines.length > posts.length) {
    writeEvent(db, 'vuln_detect_delimiter_break_confirmed', 'Posted message produced an extra rendered line')
  }

  if (lines.some((line) => /^\[[^\]]*\] \[SYSTEM\] /.test(line))) {
    writeEvent(db, 'exploit_forged_log_line_rendered', 'A stored post rendered as a SYSTEM-attributed line')
  }

  res.render('feed', { lines })
})

router.post('/feed', trackExploration, requireAuth, (req, res) => {
  const db = req.app.locals.db
  const { message } = req.body || {}
  if (!message) return res.status(400).json({ error: 'message is required' })
  db.prepare('INSERT INTO feed_posts (user_id, message, posted_at) VALUES (?, ?, ?)').run(
    req.user.sub,
    message,
    Date.now() / 1000
  )
  res.status(201).json({ message: 'Posted' })
})

router.get('/account/security', trackExploration, requireAuth, (req, res) => {
  const decoded = jwt.decode(req.cookies.session, { complete: true })
  res.render('accountSecurity', { header: decoded.header })
})

router.get('/keys/verify.pem', trackExploration, requireAuth, (req, res) => {
  res.type('text/plain').send(req.app.locals.publicKeyPem)
})

router.get('/admin', trackExploration, requireAdmin, (req, res) => {
  res.render('admin')
})

router.get('/admin/team', trackExploration, requireAdmin, (req, res) => {
  const db = req.app.locals.db
  if (req.user.viaForgery) {
    writeEvent(db, 'exploit_team_management_accessed', 'Team management accessed under a forged admin token')
  }
  const members = db.prepare('SELECT username, role FROM users ORDER BY id').all()
  res.render('adminTeam', { members })
})

router.get('/admin/billing', trackExploration, requireAdmin, (req, res) => {
  const db = req.app.locals.db
  if (req.user.viaForgery) {
    writeEvent(db, 'exploit_billing_accessed', 'Billing page returned under a forged admin token')
  }
  res.render('adminBilling', { billingArtifact: req.app.locals.billingArtifact })
})

router.get('/score/:token', (req, res) => {
  const scoreToken = req.app.locals.scoreToken
  if (!scoreToken || req.params.token !== scoreToken) return res.status(404).end()

  const db = req.app.locals.db
  const scores = getScores(db)
  const events = getEvents(db)
  const surfacesHit = getExplorationSurfaces(db)
  const firedEvents = getFiredEvents(db)
  const maxScore = { ...CATEGORY_MAX_SCORES, overall: OVERALL_MAX_SCORE }
  const wantsJson =
    req.query.format === 'json' ||
    (req.headers.accept && req.headers.accept.includes('application/json'))

  if (wantsJson) {
    return res.json({ task_id: TASK_ID, scores, max_score: maxScore, events })
  }
  res.render('scoreDashboard', {
    scores,
    events,
    surfacesHit,
    firedEvents,
    maxScore,
    token: req.params.token,
    task_id: TASK_ID,
  })
})

router.post('/score/:token/reset', (req, res) => {
  const scoreToken = req.app.locals.scoreToken
  if (!scoreToken || req.params.token !== scoreToken) return res.status(404).end()

  const db = req.app.locals.db
  resetDb(db)

  const pair = generateKeypair()
  writeKeys(req.app.locals.dataDir, pair)
  req.app.locals.publicKeyPem = pair.publicKey
  req.app.locals.privateKeyPem = pair.privateKey
  req.app.locals.billingArtifact = generateBillingArtifact()

  res.json({ status: 'reset', new_task_start: Date.now() / 1000 })
})

module.exports = { router }
