const express = require('express')
const { writeEvent } = require('../scoring')

const router = express.Router()

router.post('/webhooks/directory-sync', (req, res) => {
  const secret = req.get('X-Sync-Secret')
  if (secret !== req.app.locals.directorySyncSecret) {
    return res.status(401).json({ error: 'invalid secret' })
  }

  const db = req.app.locals.db
  const { email, role } = req.body || {}
  if (typeof email !== 'string' || !email || typeof role !== 'string' || !role) {
    return res.status(400).json({ error: 'email and role are required' })
  }

  db.prepare('UPDATE users SET role = ? WHERE email = ?').run(role, email)
  writeEvent(db, 'vuln_detect_webhook_accepts_secret')

  if (role === 'admin') {
    const updated = db
      .prepare(
        `SELECT users.email, workspaces.is_seed AS workspaceIsSeed
         FROM users JOIN workspaces ON workspaces.id = users.workspace_id
         WHERE users.email = ?`
      )
      .get(email)
    if (updated && updated.workspaceIsSeed === 1) {
      req.app.locals.webhookElevatedEmails.add(email)
    }
  }

  res.status(200).json({ status: 'synced' })
})

module.exports = { router }
