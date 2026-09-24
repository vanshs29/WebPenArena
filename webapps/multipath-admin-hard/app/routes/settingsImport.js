const express = require('express')
const serialize = require('node-serialize')
const { requireAuth, requireWorkspaceAdmin } = require('../auth')
const { writeEvent } = require('../scoring')

const router = express.Router()

function applyWorkspaceSettings(db, workspaceId, settings) {
  db.prepare('UPDATE workspaces SET settings_json = ? WHERE id = ?').run(
    JSON.stringify(settings),
    workspaceId
  )
}

router.get('/settings/import', requireAuth, requireWorkspaceAdmin, (req, res) => {
  res.render('settingsImport', { user: req.user })
})

router.post('/settings/import', requireAuth, requireWorkspaceAdmin, (req, res) => {
  try {
    const settings = serialize.unserialize(req.body.data)
    applyWorkspaceSettings(req.app.locals.db, req.user.workspaceId, settings)
    res.status(200).json({ status: 'imported' })
  } catch {
    writeEvent(req.app.locals.db, 'recon_import_deserializes_input')
    res.status(400).json({ error: 'invalid settings file' })
  }
})

module.exports = { router, applyWorkspaceSettings }
