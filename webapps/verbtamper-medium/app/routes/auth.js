const express = require('express')
const { issueSession } = require('../auth')

const router = express.Router()

router.get('/login', (req, res) => {
  res.render('login', { error: null })
})

router.post('/login', (req, res) => {
  const db = req.app.locals.db
  const { email, password } = req.body || {}
  if (typeof email !== 'string' || !email || typeof password !== 'string' || !password) {
    return res.status(401).json({ error: 'invalid credentials' })
  }
  const normalizedEmail = email.toLowerCase()
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(normalizedEmail)
  if (!user || user.password !== password) {
    return res.status(401).json({ error: 'invalid credentials' })
  }
  const token = issueSession(req.app, user)
  res.cookie('session', token, { httpOnly: true })
  res.status(200).json({ message: 'logged in' })
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
  db.prepare('INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)').run(
    username,
    normalizedEmail,
    password,
    'member'
  )
  res.status(201).json({ message: 'registered' })
})

module.exports = { router }
