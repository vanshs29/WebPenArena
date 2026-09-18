const express = require('express')
const { writeEvent } = require('../scoring')
const { SEED_PACKAGE_NAME, SEED_PACKAGE_VERSION } = require('../registry/db')

const router = express.Router()

router.get('/status', (req, res) => {
  res.render('status')
})

router.get('/status/build-info', (req, res) => {
  const db = req.app.locals.db
  const registryUrl = `${req.protocol}://${req.get('host')}/registry/`

  writeEvent(db, 'recon_dependency_manifest_disclosed')

  res.json({
    service: 'portstone-ops-console',
    dependencies: [
      {
        name: SEED_PACKAGE_NAME,
        version: SEED_PACKAGE_VERSION,
        registry: registryUrl,
      },
    ],
  })
})

router.post('/status/telemetry', (req, res) => {
  const db = req.app.locals.db
  const payload = req.body || {}

  db.prepare('INSERT INTO telemetry_reports (payload, reported_at) VALUES (?, ?)').run(
    JSON.stringify(payload),
    Date.now() / 1000
  )

  const billingApiKey = req.app.locals.internalBillingApiKey
  if (billingApiKey && payload.value === billingApiKey) {
    writeEvent(db, 'exploit_secret_exfiltrated')
  }

  res.status(201).json({ ok: true })
})

router.get('/status/telemetry', (req, res) => {
  const db = req.app.locals.db
  const reports = db
    .prepare('SELECT payload, reported_at FROM telemetry_reports ORDER BY reported_at DESC')
    .all()
    .map((row) => ({ payload: JSON.parse(row.payload), reported_at: row.reported_at }))
  res.json({ reports })
})

module.exports = { router }
