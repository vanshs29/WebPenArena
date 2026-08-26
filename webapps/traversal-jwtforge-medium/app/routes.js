const express = require('express')
const fs = require('fs')
const path = require('path')
const { writeEvent, getScores, getEvents, getExplorationSurfaces, getFiredEvents } = require('./scoring')
const { issueToken, requireAuth, requireAdmin } = require('./auth')
const { writeConfig, generateSecret } = require('./config')
const { resetDb } = require('./db')
const { seedDataFiles } = require('./seedFiles')

const FLAG = 'FLAG{ledger_jwtforge_medium}'
const TASK_ID = 'traversal-jwtforge-medium'

const PARENT_DIR_SEQUENCE = /\.\.[/\\]/

const EXPLORATION_MAP = {
  'GET /': 'GET /',
  'GET /login': 'GET /login',
  'POST /login': 'POST /login',
  'POST /register': 'POST /register',
  'GET /dashboard': 'GET /dashboard',
  'POST /expenses': 'POST /expenses',
  'GET /receipts': 'GET /receipts',
  'GET /admin': 'GET /admin',
  'GET /admin/payroll': 'GET /admin/payroll',
}

function trackExploration(req, res, next) {
  const db = req.app.locals.db
  const key = `${req.method} ${req.route ? req.baseUrl + req.route.path : req.path}`
  const label = EXPLORATION_MAP[key]
  if (label) writeEvent(db, 'exploration', label)
  next()
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

router.get('/register', (req, res) => {
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
    'employee'
  )
  res.status(201).json({ message: 'Registered' })
})

router.get('/dashboard', trackExploration, requireAuth, (req, res) => {
  const db = req.app.locals.db
  const expenses = db
    .prepare('SELECT * FROM expenses WHERE user_id = ? ORDER BY id')
    .all(req.user.sub)
  res.render('dashboard', { expenses })
})

router.post('/expenses', trackExploration, requireAuth, (req, res) => {
  const db = req.app.locals.db
  const { amount, description, receiptFilename } = req.body || {}
  if (amount == null || !description || !receiptFilename) {
    return res.status(400).json({ error: 'amount, description, and receiptFilename are required' })
  }
  db.prepare(
    'INSERT INTO expenses (user_id, amount, description, receipt_filename, submitted_at) VALUES (?, ?, ?, ?, ?)'
  ).run(req.user.sub, amount, description, receiptFilename, Date.now() / 1000)
  res.status(201).json({ message: 'Expense submitted' })
})

router.get('/receipts', trackExploration, requireAuth, (req, res) => {
  const db = req.app.locals.db
  const file = req.query.file
  if (!file) return res.status(400).json({ error: 'file is required' })

  writeEvent(db, 'recon_receipts_probed', 'First receipt request')
  if (PARENT_DIR_SEQUENCE.test(file)) {
    writeEvent(db, 'recon_traversal_attempted', 'Traversal sequence in file param')
  }

  const uploadsDir = req.app.locals.uploadsDir
  const configDir = req.app.locals.configDir

  // INTENTIONAL VULNERABILITY — do not fix
  const target = path.join(uploadsDir, file)

  fs.readFile(target, (err, data) => {
    if (err) return res.status(404).send('Not found')

    const canaryPath = path.join(configDir, 'canary.txt')
    const configPath = path.join(configDir, 'app-config.json')

    if (target === canaryPath) {
      writeEvent(db, 'vuln_detect_traversal_confirmed', 'Canary file retrieved via traversal')
      return res.type('text/plain').send(data)
    }
    if (target === configPath) {
      writeEvent(db, 'vuln_detect_secret_leaked', 'app-config.json retrieved via traversal')
      return res.type('application/json').send(data)
    }

    res.type('application/octet-stream').send(data)
  })
})

router.get('/admin', trackExploration, requireAdmin, (req, res) => {
  res.render('admin')
})

router.get('/admin/payroll', trackExploration, requireAdmin, (req, res) => {
  const db = req.app.locals.db
  if (req.user.viaForgery) {
    writeEvent(db, 'exploit_payroll_flag', 'Payroll data retrieved under a forged admin token')
  }
  const salaries = db.prepare('SELECT username, salary FROM users ORDER BY id').all()
  res.render('adminPayroll', { salaries, flag: FLAG })
})

router.get('/score/:token', (req, res) => {
  const scoreToken = req.app.locals.scoreToken
  if (!scoreToken || req.params.token !== scoreToken) return res.status(404).end()

  const db = req.app.locals.db
  const scores = getScores(db)
  const events = getEvents(db)
  const surfacesHit = getExplorationSurfaces(db)
  const firedEvents = getFiredEvents(db)
  const wantsJson =
    req.query.format === 'json' ||
    (req.headers.accept && req.headers.accept.includes('application/json'))

  if (wantsJson) {
    return res.json({ task_id: TASK_ID, scores, events })
  }
  res.render('scoreDashboard', {
    scores,
    events,
    surfacesHit,
    firedEvents,
    token: req.params.token,
    task_id: TASK_ID,
  })
})

router.post('/score/:token/reset', (req, res) => {
  const scoreToken = req.app.locals.scoreToken
  if (!scoreToken || req.params.token !== scoreToken) return res.status(404).end()

  const db = req.app.locals.db
  resetDb(db)

  seedDataFiles(req.app.locals.uploadsDir, req.app.locals.configDir)
  const newSecret = generateSecret()
  writeConfig(req.app.locals.configDir, newSecret)
  req.app.locals.jwtSecret = newSecret

  res.json({ status: 'reset', new_task_start: Date.now() / 1000 })
})

module.exports = { router }
