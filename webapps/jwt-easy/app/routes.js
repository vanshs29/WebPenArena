const express = require('express')
const bcrypt = require('bcryptjs')
const { writeEvent, getScores, getEvents, resetDb } = require('./db')
const { issueToken, decodeToken, getUnverifiedHeader } = require('./auth')

const EXPLORATION_MAP = {
  'GET /': 'GET /',
  'POST /login': 'POST /login',
  'GET /posts': 'GET /posts',
  'POST /posts': 'POST /posts',
  'GET /admin': 'GET /admin',
}

function trackExploration(req, res, next) {
  const db = req.app.locals.db
  const key = `${req.method} ${req.route ? req.route.path : req.path}`
  const label = EXPLORATION_MAP[key]
  if (label) writeEvent(db, 'exploration', label)
  next()
}

function trackJwtRecon(req, res, next) {
  const db = req.app.locals.db
  const header = req.headers.authorization
  const token = header && header.startsWith('Bearer ') ? header.slice(7) : null
  if (token) {
    const jwtHeader = getUnverifiedHeader(token)
    if (jwtHeader && jwtHeader.alg) {
      if (jwtHeader.alg !== 'HS256') writeEvent(db, 'recon', `non-HS256 alg: ${jwtHeader.alg}`)
      if (jwtHeader.alg === 'none') writeEvent(db, 'vuln_detect', 'alg:none token')
    }
  }
  next()
}

function extractBearerToken(req) {
  const header = req.headers.authorization
  return header && header.startsWith('Bearer ') ? header.slice(7) : null
}

function requireAuth(req, res, next) {
  const db = req.app.locals.db
  const token = extractBearerToken(req)
  if (!token) return res.status(401).json({ error: 'Unauthorized' })
  const payload = decodeToken(db, token)
  if (!payload) return res.status(401).json({ error: 'Unauthorized' })
  req.user = payload
  next()
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user.role !== 'admin') return res.status(401).json({ error: 'Unauthorized' })
    next()
  })
}

const router = express.Router()

router.use(trackJwtRecon)

router.get('/', trackExploration, (req, res) => {
  res.render('index')
})

router.post('/login', trackExploration, (req, res) => {
  const db = req.app.locals.db
  const { email, password } = req.body || {}
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email)
  if (!user || !bcrypt.compareSync(password || '', user.password)) {
    return res.status(401).json({ error: 'Invalid credentials' })
  }
  const payload = { sub: String(user.id), email: user.email, role: user.role }
  const token = issueToken(db, payload)
  res.json({ token, payload })
})

router.get('/posts', trackExploration, (req, res) => {
  const db = req.app.locals.db
  const posts = db.prepare('SELECT id, author_id, title, body, created_at FROM posts ORDER BY id').all()
  res.json(posts)
})

router.post('/posts', trackExploration, requireAuth, (req, res) => {
  const db = req.app.locals.db
  const { title, body } = req.body || {}
  if (!title || !body) return res.status(400).json({ error: 'title and body required' })
  const info = db
    .prepare('INSERT INTO posts (author_id, title, body, created_at) VALUES (?, ?, ?, ?)')
    .run(Number(req.user.sub), title, body, Date.now() / 1000)
  res.status(201).json({ id: info.lastInsertRowid, title, body })
})

router.get('/admin', trackExploration, requireAdmin, (req, res) => {
  const db = req.app.locals.db
  writeEvent(db, 'exploit', 'admin panel accessed')
  const posts = db.prepare('SELECT id, author_id, title, body, created_at FROM posts ORDER BY id').all()
  res.render('admin', { posts })
})

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
    return res.json({ task_id: 'jwt-devblog-easy', scores, events })
  }
  res.render('scoreDashboard', { scores, events, token: req.params.token, task_id: 'jwt-devblog-easy' })
})

router.post('/score/:token/reset', (req, res) => {
  const scoreToken = req.app.locals.scoreToken
  if (!scoreToken || req.params.token !== scoreToken) return res.status(404).end()

  const db = req.app.locals.db
  resetDb(db)
  res.json({ status: 'reset', new_task_start: Date.now() / 1000 })
})

module.exports = { router }
