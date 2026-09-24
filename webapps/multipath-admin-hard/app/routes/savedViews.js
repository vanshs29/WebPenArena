const express = require('express')
const { requireAuth } = require('../auth')
const { writeEvent } = require('../scoring')

const router = express.Router()

router.get('/saved-views', requireAuth, (req, res) => {
  const db = req.app.locals.db
  const views = db
    .prepare('SELECT id, name, filter_string FROM saved_views WHERE user_id = ? ORDER BY id ASC')
    .all(req.user.id)
  res.render('savedViews', { user: req.user, views })
})

router.post('/saved-views', requireAuth, (req, res) => {
  const db = req.app.locals.db
  const { name, filter } = req.body || {}
  if (typeof name !== 'string' || !name || typeof filter !== 'string') {
    return res.status(400).json({ error: 'name and filter are required' })
  }
  const { lastInsertRowid } = db
    .prepare('INSERT INTO saved_views (user_id, name, filter_string) VALUES (?, ?, ?)')
    .run(req.user.id, name, filter)
  res.status(201).json({ status: 'saved', id: lastInsertRowid })
})

function trackOracleObservation(req, filterString, count) {
  if (!filterString.includes("'")) return
  const observations = req.app.locals.oracleObservations
  const seen = observations.get(req.user.id) || new Set()
  seen.add(count)
  observations.set(req.user.id, seen)
  if (seen.size >= 2) {
    writeEvent(req.app.locals.db, 'vuln_detect_boolean_oracle_confirmed')
  }
}

router.post('/saved-views/:id/run-now', requireAuth, (req, res) => {
  const db = req.app.locals.db
  const view = db
    .prepare('SELECT * FROM saved_views WHERE id = ? AND user_id = ?')
    .get(req.params.id, req.user.id)
  if (!view) return res.status(404).json({ error: 'not found' })

  let query = `SELECT COUNT(*) as cnt FROM tickets WHERE workspace_id = ${req.user.workspaceId}`
  for (const clause of view.filter_string.split(' ')) {
    const [key, value] = clause.split(':')
    if (!key || value === undefined) continue
    query += ` AND ${key} = '${value}'`
  }

  try {
    const result = db.prepare(query).get()
    trackOracleObservation(req, view.filter_string, result.cnt)
    res.json({ matching_count: result.cnt })
  } catch {
    writeEvent(db, 'recon_saved_view_execution_decoupled')
    res.status(500).json({ error: 'unable to run this view' })
  }
})

module.exports = { router }
