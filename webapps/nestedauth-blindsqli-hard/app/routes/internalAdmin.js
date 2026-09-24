const express = require('express')
const { issuePlatformAdminSession, requirePlatformAdmin } = require('../auth')
const { writeEvent } = require('../scoring')

function buildRouter() {
  const router = express.Router()

  router.get('/internal/admin/login', (req, res) => {
    res.render('internalAdminLogin', {
      title: 'Platform Admin Login — Meridian',
      member: null,
      error: null,
      layout: false,
    })
  })

  router.post('/internal/admin/login', async (req, res, next) => {
    try {
      const { email, password } = req.body || {}
      if (typeof email !== 'string' || !email || typeof password !== 'string' || !password) {
        return res.status(401).json({ error: 'invalid credentials' })
      }
      const pool = req.app.locals.pool
      const { rows } = await pool.query('SELECT * FROM platform_admins WHERE email = $1', [
        email.toLowerCase(),
      ])
      const admin = rows[0]
      if (!admin || admin.password !== password) {
        return res.status(401).json({ error: 'invalid credentials' })
      }
      const token = issuePlatformAdminSession(req.app, admin)
      res.cookie('admin_session', token, { httpOnly: true })
      await writeEvent(pool, 'exploit_platform_admin_password_extracted')
      res.status(200).json({ message: 'logged in' })
    } catch (err) {
      next(err)
    }
  })

  router.get('/internal/admin/infra-runbook', requirePlatformAdmin, async (req, res, next) => {
    try {
      const pool = req.app.locals.pool
      await writeEvent(pool, 'exploit_infra_runbook_accessed')
      res.render('infraRunbook', {
        title: 'Infrastructure Runbook — Meridian',
        member: null,
        admin: req.platformAdmin,
        layout: false,
      })
    } catch (err) {
      next(err)
    }
  })

  return router
}

module.exports = { buildRouter }
