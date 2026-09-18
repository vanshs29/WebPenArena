const express = require('express')
const crypto = require('crypto')
const { writeEvent } = require('../../scoring')

const router = express.Router()

router.put('/-/user/org.couchdb.user/:name', (req, res) => {
  const db = req.app.locals.registryDb
  const username = req.params.name
  const token = crypto.randomBytes(24).toString('hex')

  try {
    db.prepare('INSERT INTO accounts (username, token) VALUES (?, ?)').run(username, token)
  } catch (err) {
    return res.status(409).json({ error: 'account already exists' })
  }

  writeEvent(req.app.locals.db, 'recon_registry_open_signup')

  res.status(201).json({
    ok: true,
    id: `org.couchdb.user:${username}`,
    rev: '0-1',
    token,
  })
})

module.exports = { router }
