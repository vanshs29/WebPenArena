const express = require('express')
const { issueSession } = require('../auth')
const { writeEvent } = require('../scoring')
const { PLATFORM_ADMIN_EMAIL } = require('../../db/seed')

const router = express.Router()

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
  if (user.email === PLATFORM_ADMIN_EMAIL) {
    writeEvent(db, 'exploit_admin_password_extracted_and_logged_in')
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
  const { workspaceName, email, password } = req.body || {}
  if (
    typeof workspaceName !== 'string' ||
    !workspaceName ||
    typeof email !== 'string' ||
    !email ||
    typeof password !== 'string' ||
    !password
  ) {
    return res.status(400).json({ error: 'workspaceName, email, and password are required' })
  }

  const existingUser = db.prepare('SELECT id FROM users WHERE email = ?').get(email)
  if (existingUser) {
    return res.status(409).json({ error: 'email already registered' })
  }

  let workspace = db.prepare('SELECT id FROM workspaces WHERE name = ?').get(workspaceName)
  let role = 'member'
  if (!workspace) {
    const { lastInsertRowid } = db
      .prepare('INSERT INTO workspaces (name, is_seed) VALUES (?, 0)')
      .run(workspaceName)
    workspace = { id: lastInsertRowid }
    role = 'admin'
  }

  db.prepare('INSERT INTO users (workspace_id, email, password, role) VALUES (?, ?, ?, ?)').run(
    workspace.id,
    email,
    password,
    role
  )

  res.status(201).json({ message: 'Registered', role })
})

module.exports = { router }
