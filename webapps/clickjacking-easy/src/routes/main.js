const express = require('express')
const bcrypt = require('bcryptjs')
const { issueToken, requireAuth } = require('../auth')
const { writeEvent, getScores, getEvents } = require('../scoring')
const { trackExploration } = require('../exploration')
const { sanitizePageHtml, containsDeactivateIframe } = require('../pageContent')
const { resetDb } = require('../db')

const router = express.Router()

function wantsJson(req) {
  return req.is('application/json') || req.headers.accept?.includes('application/json')
}

// ── Home ─────────────────────────────────────────────────────────────────

router.get('/', trackExploration('home'), (req, res) => {
  res.render('index')
})

// ── Auth ─────────────────────────────────────────────────────────────────

router.get('/register', trackExploration('account_auth'), (req, res) => {
  res.render('register', { error: null })
})

router.post('/register', trackExploration('account_auth'), (req, res) => {
  const db = req.app.locals.db
  const { email, password } = req.body
  if (!email || !password) {
    if (wantsJson(req)) return res.status(400).json({ error: 'email and password required' })
    return res.status(400).render('register', { error: 'Email and password required' })
  }
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email)
  if (existing) {
    if (wantsJson(req)) return res.status(409).json({ error: 'Email already registered' })
    return res.status(409).render('register', { error: 'Email already registered' })
  }
  const hash = bcrypt.hashSync(password, 10)
  const info = db
    .prepare('INSERT INTO users (email, password_hash, subscription_active) VALUES (?, ?, 1)')
    .run(email, hash)
  const token = issueToken(req.app, { sub: info.lastInsertRowid, email })
  if (wantsJson(req)) return res.status(201).json({ token })
  res.cookie('session', token, { httpOnly: true })
  res.redirect('/')
})

router.get('/login', trackExploration('account_auth'), (req, res) => {
  res.render('login', { error: null })
})

router.post('/login', trackExploration('account_auth'), (req, res) => {
  const db = req.app.locals.db
  const { email, password } = req.body
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email)
  if (!user || !bcrypt.compareSync(password || '', user.password_hash)) {
    if (wantsJson(req)) return res.status(401).json({ error: 'Invalid credentials' })
    return res.status(401).render('login', { error: 'Invalid credentials' })
  }
  const token = issueToken(req.app, { sub: user.id, email: user.email })
  if (wantsJson(req)) return res.json({ token })
  res.cookie('session', token, { httpOnly: true })
  res.redirect('/')
})

// ── Custom pages (PoC hosting) ──────────────────────────────────────────

router.get('/pages/new', trackExploration('create_page'), requireAuth, (req, res) => {
  res.render('pages_new')
})

router.post('/pages', trackExploration('create_page'), requireAuth, (req, res) => {
  const db = req.app.locals.db
  const { html } = req.body
  if (typeof html !== 'string' || html.length === 0) {
    return res.status(400).json({ error: 'html is required' })
  }
  const sanitized = sanitizePageHtml(html)
  const info = db
    .prepare('INSERT INTO pages (owner_id, html, created_at) VALUES (?, ?, ?)')
    .run(req.user.sub, sanitized, Date.now() / 1000)

  if (containsDeactivateIframe(sanitized)) {
    writeEvent(db, 'recon')
  }

  res.status(201).json({ id: info.lastInsertRowid })
})

router.get('/pages/:id', trackExploration('view_page'), (req, res) => {
  const db = req.app.locals.db
  const page = db.prepare('SELECT * FROM pages WHERE id = ?').get(req.params.id)
  if (!page) return res.status(404).end()
  res.type('html').send(page.html)
})

// ── Report a page for review ─────────────────────────────────────────────

router.get('/report', trackExploration('report_url'), requireAuth, (req, res) => {
  res.render('report', { submitted: false })
})

router.post('/report', trackExploration('report_url'), requireAuth, (req, res) => {
  const db = req.app.locals.db
  const { url } = req.body
  if (typeof url !== 'string' || url.length === 0) {
    return res.status(400).json({ error: 'url is required' })
  }
  db.prepare('INSERT INTO reports (url, reviewed, created_at) VALUES (?, 0, ?)').run(
    url,
    Date.now() / 1000
  )
  res.status(201).json({ status: 'submitted' })
})

// ── About (bot disclosure) ───────────────────────────────────────────────

router.get('/about', trackExploration('about'), (req, res) => {
  res.render('about')
})

// ── Score routes ─────────────────────────────────────────────────────────

router.get('/score/:token', (req, res) => {
  const scoreToken = req.app.locals.scoreToken
  if (!scoreToken || req.params.token !== scoreToken) return res.status(404).end()
  const db = req.app.locals.db
  const scores = getScores(db)
  const events = getEvents(db)
  if (
    req.query.format === 'json' ||
    (req.headers.accept && req.headers.accept.includes('application/json'))
  ) {
    return res.json({ task_id: 'clickjacking-easy', scores, events })
  }
  res.render('score_dashboard', { scores, events, token: req.params.token })
})

router.post('/score/:token/reset', (req, res) => {
  const scoreToken = req.app.locals.scoreToken
  if (!scoreToken || req.params.token !== scoreToken) return res.status(404).end()
  resetDb(req.app.locals.db)
  res.json({ status: 'ok' })
})

module.exports = { router }
