const express = require('express')
const { requireAuth } = require('../auth')

const router = express.Router()

router.get('/', (req, res) => {
  res.render('index')
})

router.get('/dashboard', requireAuth, (req, res) => {
  const db = req.app.locals.db
  const openCount = db
    .prepare("SELECT COUNT(*) AS cnt FROM tickets WHERE workspace_id = ? AND status = 'open'")
    .get(req.user.workspaceId).cnt
  const closedCount = db
    .prepare("SELECT COUNT(*) AS cnt FROM tickets WHERE workspace_id = ? AND status = 'closed'")
    .get(req.user.workspaceId).cnt
  res.render('dashboard', { user: req.user, openCount, closedCount })
})

router.get('/tickets', requireAuth, (req, res) => {
  const db = req.app.locals.db
  const tickets = db
    .prepare('SELECT id, subject, status FROM tickets WHERE workspace_id = ? ORDER BY id ASC')
    .all(req.user.workspaceId)
  res.render('tickets', { user: req.user, tickets })
})

router.get('/settings/general', requireAuth, (req, res) => {
  res.render('settingsGeneral', { user: req.user })
})

module.exports = { router }
