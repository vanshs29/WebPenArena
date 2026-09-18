const express = require('express')
const { issueSession, requireAuth } = require('../auth')
const { trackExploration } = require('../scoring')

const EXPLORATION_MAP = {
  'GET /login': 'GET /login',
  'POST /login': 'POST /login',
  'GET /register': 'GET /register',
  'POST /register': 'POST /register',
}

const router = express.Router()

router.use(trackExploration(EXPLORATION_MAP))

router.get('/login', (req, res) => {
  res.render('login', { error: null })
})

router.post('/login', (req, res) => {
  const db = req.app.locals.db
  const { email, password } = req.body || {}
  if (typeof email !== 'string' || !email || typeof password !== 'string' || !password) {
    return res.status(401).json({ error: 'Invalid credentials' })
  }
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email)
  if (!user || user.password !== password) {
    return res.status(401).json({ error: 'Invalid credentials' })
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
  const existing = db
    .prepare('SELECT id FROM users WHERE email = ? OR username = ?')
    .get(email, username)
  if (existing) {
    return res.status(409).json({ error: 'email or username already registered' })
  }
  db.prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)').run(
    username,
    email,
    password
  )
  res.status(201).json({ message: 'Registered' })
})

module.exports = { router, requireAuth }
