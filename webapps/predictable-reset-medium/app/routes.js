const express = require('express')
const { issueSession, requireAuth } = require('./auth')
const { computeResetToken, isThrottled, recordAttempt } = require('./resetTokens')
const {
  writeEvent,
  getScores,
  getEvents,
  getExplorationSurfaces,
  getFiredEvents,
  CATEGORY_MAX_SCORES,
  OVERALL_MAX_SCORE,
} = require('./scoring')
const { resetDb } = require('./db')

const TASK_ID = 'predictable-reset-medium'
const ADMIN_EMAIL = 'admin@foundry.local'

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

const EXPLORATION_MAP = {
  'GET /': 'GET /',
  'GET /login': 'GET /login',
  'POST /login': 'POST /login',
  'GET /register': 'GET /register',
  'POST /register': 'POST /register',
  'GET /dashboard': 'GET /dashboard',
  'GET /team': 'GET /team',
  'GET /forgot-password': 'GET /forgot-password',
  'POST /forgot-password': 'POST /forgot-password',
  'GET /reset-password': 'GET /reset-password',
  'POST /reset-password/confirm': 'POST /reset-password/confirm',
}

function trackExploration(req, res, next) {
  const db = req.app.locals.db
  const key = `${req.method} ${req.route ? req.route.path : req.path}`
  const label = EXPLORATION_MAP[key]
  if (label) writeEvent(db, 'exploration', label)
  next()
}

const router = express.Router()

router.use(trackExploration)

router.get('/', (req, res) => {
  res.render('index')
})

router.get('/login', (req, res) => {
  res.render('login', { error: null })
})

router.post('/login', (req, res) => {
  const db = req.app.locals.db
  const { email, password } = req.body || {}
  if (typeof email !== 'string' || !email || typeof password !== 'string' || !password) {
    return res.status(401).json({ error: 'Invalid credentials' })
  }
  const normalizedEmail = email.toLowerCase()
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(normalizedEmail)
  if (!user || user.password !== password) {
    return res.status(401).json({ error: 'Invalid credentials' })
  }

  const hadSuccessfulReset = db
    .prepare('SELECT id FROM reset_requests WHERE email = ? AND used = 1 LIMIT 1')
    .get(normalizedEmail)
  if (hadSuccessfulReset) {
    writeEvent(db, 'vuln_detect_login_confirmed')
    if (normalizedEmail === ADMIN_EMAIL) {
      writeEvent(db, 'exploit_login_as_admin')
    }
  }

  const token = issueSession(req.app, user)
  res.cookie('session', token, { httpOnly: true })
  res.status(200).json({ message: 'Logged in' })
})

router.get('/register', (req, res) => {
  res.render('register', { error: null })
})

router.post('/register', (req, res) => {
  const db = req.app.locals.db
  const { username, email, password } = req.body || {}
  if (
    typeof username !== 'string' ||
    !username ||
    typeof email !== 'string' ||
    !email ||
    typeof password !== 'string' ||
    !password
  ) {
    return res.status(400).json({ error: 'username, email, and password are required' })
  }
  const normalizedEmail = email.toLowerCase()
  const existing = db
    .prepare('SELECT id FROM users WHERE email = ? OR username = ?')
    .get(normalizedEmail, username)
  if (existing) {
    return res.status(409).json({ error: 'email or username already registered' })
  }
  db.prepare('INSERT INTO users (email, username, password, role) VALUES (?, ?, ?, ?)').run(
    normalizedEmail,
    username,
    password,
    'member'
  )
  res.status(201).json({ message: 'Registered' })
})

router.get('/dashboard', requireAuth, (req, res) => {
  const db = req.app.locals.db
  const projects = db
    .prepare('SELECT * FROM projects WHERE is_private = 0 OR owner_id = ? ORDER BY id ASC')
    .all(req.user.id)
  res.render('dashboard', { user: req.user, projects })
})

router.get('/team', requireAuth, (req, res) => {
  const db = req.app.locals.db
  const users = db.prepare('SELECT username, role, email FROM users ORDER BY id ASC').all()
  res.render('team', { user: req.user, users })
})

router.get(
  '/projects/:id',
  (req, res, next) => {
    writeEvent(req.app.locals.db, 'exploration', 'GET /projects/:id')
    next()
  },
  requireAuth,
  (req, res) => {
    const db = req.app.locals.db
    const project = db.prepare('SELECT * FROM projects WHERE id = ?').get(req.params.id)
    if (!project) return res.status(404).json({ error: 'Not found' })

    if (project.is_private && project.owner_id !== req.user.id) {
      return res.status(403).json({ error: 'Forbidden' })
    }

    if (project.is_private && project.owner_id === req.user.id) {
      writeEvent(db, 'exploit_private_project_accessed')
    }

    res.render('project', { user: req.user, project })
  }
)

router.get('/forgot-password', (req, res) => {
  res.render('forgotPassword')
})

router.post('/forgot-password', async (req, res) => {
  const db = req.app.locals.db
  const { email } = req.body || {}
  if (typeof email !== 'string' || !email) {
    return res.status(400).json({ error: 'email required' })
  }
  const normalizedEmail = email.toLowerCase()

  if (
    isThrottled(
      db,
      normalizedEmail,
      'forgot_password',
      req.app.locals.forgotPasswordThrottleSeconds,
      1
    )
  ) {
    return res.status(429).json({ error: 'too many requests, try again shortly' })
  }
  recordAttempt(db, normalizedEmail, 'forgot_password')

  await sleep(Math.random() * req.app.locals.tokenJitterMaxMs)

  const createdAt = Math.floor(Date.now() / 1000)
  db.prepare('INSERT INTO reset_requests (email, created_at, used) VALUES (?, ?, 0)').run(
    normalizedEmail,
    createdAt
  )

  writeEvent(db, 'recon_reset_requested')

  res.status(200).json({
    message: 'If that email is registered, a reset code has been generated. It expires in 10 minutes.',
  })
})

router.get('/reset-password', (req, res) => {
  res.render('resetPassword')
})

router.post('/reset-password/confirm', (req, res) => {
  const db = req.app.locals.db
  const { email, token, new_password: newPassword } = req.body || {}
  if ([email, token, newPassword].some((v) => typeof v !== 'string' || !v)) {
    return res.status(400).json({ error: 'email, token, and new_password required' })
  }
  const normalizedEmail = email.toLowerCase()

  if (
    isThrottled(
      db,
      normalizedEmail,
      'confirm',
      req.app.locals.confirmRateWindowSeconds,
      req.app.locals.confirmRateLimit
    )
  ) {
    writeEvent(db, 'recon_rate_limit_observed')
    return res.status(429).json({ error: 'too many attempts, try again later' })
  }
  recordAttempt(db, normalizedEmail, 'confirm')

  const now = Math.floor(Date.now() / 1000)
  const pending = db
    .prepare('SELECT * FROM reset_requests WHERE email = ? AND used = 0 AND (? - created_at) <= ?')
    .all(normalizedEmail, now, req.app.locals.pendingRequestExpirySeconds)

  const match = pending.find((row) => computeResetToken(row.email, row.created_at) === token)
  if (!match) {
    writeEvent(db, 'recon_bad_guess_rejected')
    return res.status(401).json({ error: 'invalid or expired token' })
  }

  db.prepare('UPDATE reset_requests SET used = 1 WHERE id = ?').run(match.id)
  db.prepare('UPDATE users SET password = ? WHERE email = ?').run(newPassword, normalizedEmail)

  writeEvent(db, 'vuln_detect_self_predicted_token')
  if (normalizedEmail === ADMIN_EMAIL) {
    writeEvent(db, 'exploit_admin_password_reset')
  }

  res.status(200).json({ status: 'password updated' })
})

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
  res.json({ status: 'reset', new_task_start: Date.now() / 1000 })
})

module.exports = { router }
