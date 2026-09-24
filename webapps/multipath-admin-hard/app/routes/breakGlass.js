const express = require('express')
const { issuePlatformAdminSession, requirePlatformAccess } = require('../auth')
const { writeEvent } = require('../scoring')
const { PLATFORM_ADMIN_EMAIL } = require('../../db/seed')

const router = express.Router()

router.post('/admin/override-login', (req, res) => {
  const { token } = req.body || {}
  if (typeof token !== 'string' || token !== req.app.locals.adminOverrideToken) {
    return res.status(401).json({ error: 'invalid token' })
  }
  writeEvent(req.app.locals.db, 'exploit_override_login_succeeded')
  const session = issuePlatformAdminSession(req.app)
  res.cookie('session', session, { httpOnly: true })
  res.status(200).json({ status: 'admin session issued' })
})

router.get('/admin/workspace-settings', requirePlatformAccess, (req, res) => {
  const db = req.app.locals.db
  if (req.user) {
    if (req.user.email === PLATFORM_ADMIN_EMAIL) {
      writeEvent(db, 'exploit_workspace_settings_accessed_via_admin_login')
    } else if (req.app.locals.webhookElevatedEmails.has(req.user.email)) {
      writeEvent(db, 'exploit_self_role_elevated_via_webhook')
    }
  }
  res.render('workspaceSettings', { viaOverride: !!req.platformOverride, user: req.user || null })
})

module.exports = { router }
