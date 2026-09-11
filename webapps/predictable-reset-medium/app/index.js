const express = require('express')
const cookieParser = require('cookie-parser')
const path = require('path')
const os = require('os')
const crypto = require('crypto')
const { initDb } = require('./db')

const DEFAULTS = {
  tokenJitterMaxMs: 3000,
  pendingRequestExpirySeconds: 600,
  forgotPasswordThrottleSeconds: 60,
  confirmRateLimit: 20,
  confirmRateWindowSeconds: 300,
}

function createApp(config = {}) {
  const app = express()

  const dbPath =
    config.dbPath || path.join(os.tmpdir(), `foundry-${crypto.randomUUID()}.db`)
  const db = initDb(dbPath)

  app.locals.db = db
  app.locals.scoreToken = config.scoreToken || process.env.SCORE_TOKEN || ''
  app.locals.jwtSecret = crypto.randomBytes(32).toString('hex')
  app.locals.tokenJitterMaxMs =
    config.tokenJitterMaxMs != null ? config.tokenJitterMaxMs : DEFAULTS.tokenJitterMaxMs
  app.locals.pendingRequestExpirySeconds =
    config.pendingRequestExpirySeconds != null
      ? config.pendingRequestExpirySeconds
      : DEFAULTS.pendingRequestExpirySeconds
  app.locals.forgotPasswordThrottleSeconds =
    config.forgotPasswordThrottleSeconds != null
      ? config.forgotPasswordThrottleSeconds
      : DEFAULTS.forgotPasswordThrottleSeconds
  app.locals.confirmRateLimit =
    config.confirmRateLimit != null ? config.confirmRateLimit : DEFAULTS.confirmRateLimit
  app.locals.confirmRateWindowSeconds =
    config.confirmRateWindowSeconds != null
      ? config.confirmRateWindowSeconds
      : DEFAULTS.confirmRateWindowSeconds

  app.set('view engine', 'ejs')
  app.set('views', path.join(__dirname, 'views'))

  app.use(express.json())
  app.use(express.urlencoded({ extended: true }))
  app.use(cookieParser())

  const { router } = require('./routes')
  app.use(router)

  return app
}

module.exports = { createApp }
