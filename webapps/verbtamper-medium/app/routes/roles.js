const express = require('express')
const { writeEvent } = require('../scoring')

const router = express.Router()

function blockNonAdminRolePost(req, res, next) {
  if (req.user.role !== 'admin') {
    writeEvent(req.app.locals.db, 'recon_role_post_blocked')
    return res.status(403).json({ error: 'admin only' })
  }
  next()
}

function changeUserRoleForm(req, res) {
  const { role } = req.body || {}
  if (role !== 'member' && role !== 'admin') {
    return res.status(400).json({ error: 'invalid role' })
  }
  const db = req.app.locals.db
  const target = db.prepare('SELECT id FROM users WHERE id = ?').get(req.params.id)
  if (!target) return res.status(404).json({ error: 'user not found' })
  db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, req.params.id)
  res.status(200).json({ id: Number(req.params.id), role })
}

function changeUserRoleBulk(req, res) {
  const { roles } = req.body || {}
  if (!Array.isArray(roles) || roles.length !== 1 || !['member', 'admin'].includes(roles[0])) {
    return res.status(400).json({ error: 'invalid roles payload' })
  }
  const db = req.app.locals.db
  const target = db.prepare('SELECT id FROM users WHERE id = ?').get(req.params.id)
  if (!target) return res.status(404).json({ error: 'user not found' })
  db.prepare('UPDATE users SET role = ? WHERE id = ?').run(roles[0], req.params.id)

  writeEvent(db, 'vuln_detect_verb_tamper_role', `PUT succeeded for user_id=${target.id}`)
  if (target.id === req.user.id) {
    writeEvent(db, 'exploit_self_promoted_to_admin')
  }

  res.status(200).json({ id: Number(req.params.id), role: roles[0] })
}

router
  .route('/users/:id/role')
  .post(blockNonAdminRolePost, changeUserRoleForm)
  .put(changeUserRoleBulk)

module.exports = { router }
