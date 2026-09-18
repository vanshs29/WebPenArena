const express = require('express')
const { requireAuth } = require('../auth')
const { requireWorkspaceAdmin } = require('../authz')
const { writeEvent, hasFired } = require('../scoring')

function buildRouter(db) {
  const router = express.Router()

  router.post(
    '/admin/promote',
    requireAuth,
    requireWorkspaceAdmin(db, { reconMetric: 'recon_promote_gate_confirmed' }),
    (req, res) => {
      const before = db.prepare('SELECT role FROM memberships WHERE user_id = ?').get(req.user.id)
      db.prepare('UPDATE memberships SET role = ? WHERE user_id = ?').run('admin', req.user.id)
      if (!before || before.role !== 'admin') {
        writeEvent(db, 'vuln_detect_promote_failopen')
      }
      res.json({ ok: true })
    }
  )

  router.get('/admin/export', requireAuth, requireWorkspaceAdmin(db), (req, res) => {
    if (hasFired(db, 'vuln_detect_promote_failopen') && !Array.isArray(req.query.workspace_id)) {
      writeEvent(db, 'vuln_detect_admin_access_confirmed')
    }

    const membership = db
      .prepare('SELECT workspace_id FROM memberships WHERE user_id = ?')
      .get(req.user.id)
    const users = db
      .prepare(
        'SELECT u.id, u.email FROM users u JOIN memberships m ON m.user_id = u.id WHERE m.workspace_id = ?'
      )
      .all(membership.workspace_id)
    const tickets = db
      .prepare('SELECT id, subject, body, owner_id FROM tickets WHERE workspace_id = ?')
      .all(membership.workspace_id)

    writeEvent(db, 'exploit_workspace_export_used')
    res.json({ users, tickets })
  })

  return router
}

module.exports = { buildRouter }
