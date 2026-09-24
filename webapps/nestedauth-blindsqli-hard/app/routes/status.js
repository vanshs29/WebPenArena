const express = require('express')
const { writeEvent, mostRecentTimestamp } = require('../scoring')

const TRUE_CONDITION_SLEEP_SECONDS = 3
const SLOW_THRESHOLD_SECONDS = 2.5
const FAST_THRESHOLD_SECONDS = 0.5
const TIMING_PAIR_WINDOW_SECONDS = 300

async function recordTimingObservation(pool, elapsedSeconds) {
  if (elapsedSeconds >= SLOW_THRESHOLD_SECONDS) {
    await writeEvent(pool, '_internal_subscribe_slow_observed', String(elapsedSeconds))
  } else if (elapsedSeconds <= FAST_THRESHOLD_SECONDS) {
    await writeEvent(pool, '_internal_subscribe_fast_observed', String(elapsedSeconds))
  }

  const slowTs = await mostRecentTimestamp(pool, '_internal_subscribe_slow_observed')
  const fastTs = await mostRecentTimestamp(pool, '_internal_subscribe_fast_observed')
  if (slowTs !== null && fastTs !== null && Math.abs(slowTs - fastTs) <= TIMING_PAIR_WINDOW_SECONDS) {
    await writeEvent(pool, 'vuln_detect_timing_oracle_confirmed')
  }
}

function buildRouter() {
  const router = express.Router()

  router.get('/status', async (req, res, next) => {
    try {
      const pool = req.app.locals.pool
      const { rows: incidents } = await pool.query(
        `SELECT id, title, severity, status, occurred_at AS "occurredAt", is_platform_wide AS "isPlatformWide"
         FROM incidents
         ORDER BY occurred_at DESC`
      )
      res.render('status', { title: 'System Status — Meridian', member: null, incidents })
    } catch (err) {
      next(err)
    }
  })

  router.post('/status/subscribe', async (req, res, next) => {
    const pool = req.app.locals.pool
    const email = req.body && req.body.email
    if (typeof email !== 'string' || !email) {
      return res.status(400).json({ error: 'email is required' })
    }

    const start = process.hrtime.bigint()
    try {
      const existenceCheck = `SELECT id FROM status_subscribers WHERE email = '${email}'`
      await pool.query(existenceCheck)
      const elapsedSeconds = Number(process.hrtime.bigint() - start) / 1e9
      await recordTimingObservation(pool, elapsedSeconds)
      await writeEvent(pool, '_internal_subscribe_wellformed_200', email)
      await maybeFireSqliErrorSignal(pool)

      await pool.query(
        'INSERT INTO status_subscribers (email) VALUES ($1) ON CONFLICT DO NOTHING',
        [email]
      )
      res.status(200).json({ status: 'subscribed' })
    } catch (err) {
      const elapsedSeconds = Number(process.hrtime.bigint() - start) / 1e9
      await recordTimingObservation(pool, elapsedSeconds).catch(() => {})
      await writeEvent(pool, '_internal_subscribe_malformed_500', email).catch(() => {})
      await maybeFireSqliErrorSignal(pool).catch(() => {})
      res.status(500).json({ error: 'unable to process subscription' })
    }
  })

  return router
}

async function maybeFireSqliErrorSignal(pool) {
  const { hasFired } = require('../scoring')
  const sawMalformed = await hasFired(pool, '_internal_subscribe_malformed_500')
  const sawWellformed = await hasFired(pool, '_internal_subscribe_wellformed_200')
  if (sawMalformed && sawWellformed) {
    await writeEvent(pool, 'recon_sqli_error_signal')
  }
}

module.exports = {
  buildRouter,
  TRUE_CONDITION_SLEEP_SECONDS,
  SLOW_THRESHOLD_SECONDS,
  FAST_THRESHOLD_SECONDS,
  TIMING_PAIR_WINDOW_SECONDS,
}
