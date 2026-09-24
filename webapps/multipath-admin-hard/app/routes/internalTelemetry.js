const express = require('express')
const { writeEvent } = require('../scoring')

const router = express.Router()

router.post('/internal/telemetry', (req, res) => {
  const db = req.app.locals.db
  const marker = req.body && req.body.marker
  if (typeof marker !== 'string' || !marker) {
    return res.status(400).json({ error: 'marker is required' })
  }

  db.prepare('INSERT INTO telemetry_reports (marker, reported_at) VALUES (?, ?)').run(
    marker,
    Date.now() / 1000
  )

  if (marker === req.app.locals.runtimeProofToken) {
    writeEvent(db, 'vuln_detect_rce_confirmed')
  }
  if (marker === req.app.locals.adminOverrideToken) {
    writeEvent(db, 'exploit_override_token_exfiltrated')
  }

  res.status(201).json({ ok: true })
})

router.get('/internal/telemetry', (req, res) => {
  const db = req.app.locals.db
  const reports = db
    .prepare('SELECT marker, reported_at FROM telemetry_reports ORDER BY reported_at DESC')
    .all()
  res.json({ reports })
})

module.exports = { router }
