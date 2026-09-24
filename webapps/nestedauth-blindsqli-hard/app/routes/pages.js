const express = require('express')
const { requireAuth } = require('../auth')

function buildRouter() {
  const router = express.Router()

  router.get('/dashboard', requireAuth, async (req, res, next) => {
    try {
      const pool = req.app.locals.pool
      const { rows: orgRows } = await pool.query('SELECT name FROM organizations WHERE id = $1', [
        req.member.orgId,
      ])
      const { rows: incidentRows } = await pool.query(
        `SELECT incidents.status, COUNT(*)::int AS count
         FROM incidents
         JOIN incident_participants ip ON ip.incident_id = incidents.id
         WHERE ip.org_id = $1
         GROUP BY incidents.status`,
        [req.member.orgId]
      )
      res.render('dashboard', {
        title: 'Dashboard — Meridian',
        member: req.member,
        orgName: orgRows[0] ? orgRows[0].name : '',
        incidentCounts: incidentRows,
      })
    } catch (err) {
      next(err)
    }
  })

  router.get('/incidents', requireAuth, async (req, res, next) => {
    try {
      const pool = req.app.locals.pool
      const { rows: incidents } = await pool.query(
        `SELECT incidents.id, incidents.title, incidents.severity, incidents.status,
                incidents.occurred_at AS "occurredAt", incidents.is_platform_wide AS "isPlatformWide"
         FROM incidents
         JOIN incident_participants ip ON ip.incident_id = incidents.id
         WHERE ip.org_id = $1
         ORDER BY incidents.occurred_at DESC`,
        [req.member.orgId]
      )
      res.render('incidents', { title: 'Incidents — Meridian', member: req.member, incidents })
    } catch (err) {
      next(err)
    }
  })

  router.get('/team', requireAuth, async (req, res, next) => {
    try {
      const pool = req.app.locals.pool
      const { rows: roster } = await pool.query(
        'SELECT id, name, email, role FROM members WHERE org_id = $1 ORDER BY name',
        [req.member.orgId]
      )
      res.render('team', { title: 'Team — Meridian', member: req.member, roster })
    } catch (err) {
      next(err)
    }
  })

  router.get('/integrations', requireAuth, async (req, res, next) => {
    try {
      const pool = req.app.locals.pool
      const { rows: teamRows } = await pool.query(
        'SELECT id, name FROM teams WHERE org_id = $1 LIMIT 1',
        [req.member.orgId]
      )
      const team = teamRows[0] || null
      res.render('integrations', {
        title: 'Integrations — Meridian',
        member: req.member,
        team,
      })
    } catch (err) {
      next(err)
    }
  })

  router.get('/marketplace', requireAuth, async (req, res, next) => {
    try {
      res.render('marketplace', { title: 'Marketplace — Meridian', member: req.member })
    } catch (err) {
      next(err)
    }
  })

  router.get('/partners', requireAuth, async (req, res, next) => {
    try {
      res.render('partners', { title: 'Partner Directory — Meridian', member: req.member })
    } catch (err) {
      next(err)
    }
  })

  router.get('/developers', requireAuth, async (req, res, next) => {
    try {
      res.render('developers', { title: 'Developer Docs — Meridian', member: req.member })
    } catch (err) {
      next(err)
    }
  })

  return router
}

module.exports = { buildRouter }
