const express = require('express')
const crypto = require('crypto')
const { issueSession } = require('../auth')

function generateWebhookSecret() {
  return `whsec_${crypto.randomBytes(16).toString('hex')}`
}

function buildRouter() {
  const router = express.Router()

  router.get('/login', (req, res) => {
    res.render('login', { error: null })
  })

  router.post('/login', async (req, res, next) => {
    try {
      const { email, password } = req.body || {}
      if (typeof email !== 'string' || !email || typeof password !== 'string' || !password) {
        return res.status(401).json({ error: 'invalid credentials' })
      }
      const pool = req.app.locals.pool
      const normalizedEmail = email.toLowerCase()
      const { rows } = await pool.query('SELECT * FROM members WHERE email = $1', [
        normalizedEmail,
      ])
      const member = rows[0]
      if (!member || member.password !== password) {
        return res.status(401).json({ error: 'invalid credentials' })
      }
      const token = issueSession(req.app, member)
      res.cookie('session', token, { httpOnly: true })
      res.status(200).json({ message: 'logged in' })
    } catch (err) {
      next(err)
    }
  })

  router.get('/register', (req, res) => {
    res.render('register', { error: null })
  })

  router.post('/register', async (req, res, next) => {
    try {
      const { orgName, name, email, password } = req.body || {}
      if (
        typeof orgName !== 'string' ||
        !orgName ||
        typeof name !== 'string' ||
        !name ||
        typeof email !== 'string' ||
        !email ||
        typeof password !== 'string' ||
        !password
      ) {
        return res.status(400).json({ error: 'orgName, name, email, and password are required' })
      }
      const pool = req.app.locals.pool
      const normalizedEmail = email.toLowerCase()

      const existing = await pool.query('SELECT id FROM members WHERE email = $1', [
        normalizedEmail,
      ])
      if (existing.rows.length > 0) {
        return res.status(409).json({ error: 'email already registered' })
      }

      const existingOrg = await pool.query('SELECT id FROM organizations WHERE name = $1', [
        orgName,
      ])
      if (existingOrg.rows.length > 0) {
        return res.status(409).json({ error: 'organization name already taken' })
      }

      const { rows: orgRows } = await pool.query(
        'INSERT INTO organizations (name, is_seed) VALUES ($1, FALSE) RETURNING id',
        [orgName]
      )
      const orgId = orgRows[0].id

      const { rows: teamRows } = await pool.query(
        'INSERT INTO teams (org_id, name) VALUES ($1, $2) RETURNING id',
        [orgId, 'Engineering']
      )
      await pool.query(
        `INSERT INTO integrations (team_id, name, description, credentials, is_marketplace_listed)
         VALUES ($1, $2, $3, $4, FALSE)`,
        [
          teamRows[0].id,
          'Getting Started Webhook',
          'A starter webhook integration created automatically for your new organization.',
          generateWebhookSecret(),
        ]
      )

      const { rows: memberRows } = await pool.query(
        `INSERT INTO members (org_id, name, email, password, role)
         VALUES ($1, $2, $3, $4, 'org_admin') RETURNING id, org_id AS "orgId", name, email, role`,
        [orgId, name, normalizedEmail, password]
      )

      res.status(201).json({ message: 'registered', member: memberRows[0] })
    } catch (err) {
      next(err)
    }
  })

  return router
}

module.exports = { buildRouter }
