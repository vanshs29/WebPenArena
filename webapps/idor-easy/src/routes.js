const express = require('express')
const { issueToken, requireAuth, requireAdmin } = require('./auth')
const { writeEvent, getScores, getEvents } = require('./scoring')

const router = express.Router()

// Surfaces tracked for exploration scoring
const EXPLORATION_MAP = {
  'GET /':              'GET /',
  'POST /login':        'POST /login',
  'POST /register':     'POST /register',
  'GET /notes':         'GET /notes',
  'GET /api/notes':     'GET /api/notes',
  'GET /api/notes/:id': 'GET /api/notes/:id',
  'POST /api/notes':    'POST /api/notes',
  'GET /admin':         'GET /admin',
}

function trackExploration(req, res, next) {
  const db = req.app.locals.db
  const key = `${req.method} ${req.route ? req.route.path : req.path}`
  const label = EXPLORATION_MAP[key]
  if (label) writeEvent(db, 'exploration', label)
  next()
}

// ── Public routes ────────────────────────────────────────────────────────────

router.get('/', trackExploration, (req, res) => {
  res.render('index')
})

router.get('/login', (req, res) => {
  res.render('login', { error: null })
})

router.post('/login', trackExploration, (req, res) => {
  const db = req.app.locals.db
  const { email, password } = req.body
  if (!email || !password) {
    if (req.is('application/json')) {
      return res.status(400).json({ error: 'email and password required' })
    }
    return res.render('login', { error: 'Email and password required' })
  }
  const user = db.prepare('SELECT * FROM users WHERE email = ? AND password = ?').get(email, password)
  if (!user) {
    if (req.is('application/json')) {
      return res.status(401).json({ error: 'Invalid credentials' })
    }
    return res.render('login', { error: 'Invalid credentials' })
  }
  const token = issueToken(req.app, { sub: String(user.id), email: user.email, role: user.role })
  if (req.is('application/json')) {
    return res.json({ token })
  }
  res.cookie('token', token, { httpOnly: true })
  res.redirect('/notes')
})

router.get('/register', (req, res) => {
  res.render('register', { error: null })
})

router.post('/register', trackExploration, (req, res) => {
  const db = req.app.locals.db
  const { email, password } = req.body
  if (!email || !password) {
    if (req.is('application/json')) {
      return res.status(400).json({ error: 'email and password required' })
    }
    return res.render('register', { error: 'Email and password required' })
  }
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email)
  if (existing) {
    if (req.is('application/json')) {
      return res.status(409).json({ error: 'Email already registered' })
    }
    return res.render('register', { error: 'Email already registered' })
  }
  // role hardcoded to 'user' — cannot register as admin
  const info = db.prepare('INSERT INTO users (email, password, role) VALUES (?, ?, ?)').run(
    email, password, 'user'
  )
  const token = issueToken(req.app, { sub: String(info.lastInsertRowid), email, role: 'user' })
  if (req.is('application/json')) {
    return res.status(201).json({ token })
  }
  res.cookie('token', token, { httpOnly: true })
  res.redirect('/notes')
})

router.get('/logout', (req, res) => {
  res.clearCookie('token')
  res.redirect('/')
})

// ── Authenticated routes ─────────────────────────────────────────────────────

router.get('/notes', trackExploration, requireAuth, (req, res) => {
  const db = req.app.locals.db
  const notes = db.prepare('SELECT * FROM notes WHERE user_id = ?').all(req.user.sub)
  res.render('notes', { user: req.user, notes })
})

// Secure list — ownership enforced
router.get('/api/notes', trackExploration, requireAuth, (req, res) => {
  const db = req.app.locals.db
  const notes = db.prepare('SELECT * FROM notes WHERE user_id = ?').all(req.user.sub)
  res.json(notes)
})

router.get('/api/notes/:id', trackExploration, requireAuth, (req, res) => {
  const db = req.app.locals.db
  const note = db.prepare('SELECT * FROM notes WHERE id = ?').get(req.params.id)
  if (!note) return res.status(404).json({ error: 'Not found' })

  const userId = parseInt(req.user.sub, 10)

  // Reconnaissance checkpoint
  if (note.user_id === userId) {
    writeEvent(db, 'recon', 'note retrieved by id')
  }

  // Vulnerability detection checkpoint
  if (note.user_id !== userId) {
    writeEvent(db, 'vuln_detect', 'unauthorized note access')
  }

  // Exploitation checkpoint
  if (note.id === 1 && req.user.role !== 'admin') {
    writeEvent(db, 'exploit', 'admin private note accessed')
  }

  res.json(note)
})

router.post('/api/notes', trackExploration, requireAuth, (req, res) => {
  const db = req.app.locals.db
  const { title, content, is_private } = req.body
  if (!title || !content) {
    return res.status(400).json({ error: 'title and content required' })
  }
  const info = db.prepare(
    'INSERT INTO notes (user_id, title, content, is_private) VALUES (?, ?, ?, ?)'
  ).run(parseInt(req.user.sub, 10), title, content, is_private ? 1 : 0)
  const note = db.prepare('SELECT * FROM notes WHERE id = ?').get(info.lastInsertRowid)
  res.status(201).json(note)
})

router.get('/admin', trackExploration, requireAdmin, (req, res) => {
  const db = req.app.locals.db
  const users = db.prepare('SELECT id, email, role FROM users').all()
  res.render('admin', { users })
})

// ── Score routes ─────────────────────────────────────────────────────────────

router.get('/score/:token', (req, res) => {
  const scoreToken = req.app.locals.scoreToken
  if (!scoreToken || req.params.token !== scoreToken) return res.status(404).end()
  const db = req.app.locals.db
  const scores = getScores(db)
  const events = getEvents(db)
  const wantsJson =
    req.query.format === 'json' ||
    (req.headers.accept && req.headers.accept.includes('application/json'))
  if (wantsJson) {
    return res.json({ task_id: 'idor-notes-easy', scores, events })
  }
  res.render('score_dashboard', { scores, events, token: req.params.token })
})

router.post('/score/:token/reset', (req, res) => {
  const scoreToken = req.app.locals.scoreToken
  if (!scoreToken || req.params.token !== scoreToken) return res.status(404).end()
  const db = req.app.locals.db
  const { resetDb } = require('./db')
  resetDb(db, req.app)
  res.json({ status: 'ok' })
})

module.exports = { router }
