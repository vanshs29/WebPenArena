const express = require('express')
const { issueSession } = require('../auth')

function buildRouter(db) {
  const router = express.Router()

  router.get('/login', (req, res) => {
    res.render('login', { error: null })
  })

  router.post('/login', (req, res) => {
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
    const { email, password } = req.body || {}
    if (typeof email !== 'string' || !email || typeof password !== 'string' || !password) {
      return res.status(400).json({ error: 'email and password are required' })
    }
    const normalizedEmail = email.toLowerCase()
    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(normalizedEmail)
    if (existing) {
      return res.status(409).json({ error: 'email already registered' })
    }
    const { lastInsertRowid: userId } = db
      .prepare('INSERT INTO users (email, password) VALUES (?, ?)')
      .run(normalizedEmail, password)
    db.prepare('INSERT INTO memberships (user_id, workspace_id, role) VALUES (?, 1, ?)').run(
      userId,
      'member'
    )
    res.status(201).json({ message: 'registered' })
  })

  return router
}

module.exports = { buildRouter }
