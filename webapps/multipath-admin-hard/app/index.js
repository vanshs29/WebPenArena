const express = require('express')
const cookieParser = require('cookie-parser')
const crypto = require('crypto')
const path = require('path')
const os = require('os')
const { initDb } = require('./db')

function createApp(config = {}) {
  const app = express()

  const dbPath = config.dbPath || path.join(os.tmpdir(), `thornfield-${crypto.randomUUID()}.db`)
  const { db } = initDb(dbPath)

  app.locals.db = db
  app.locals.scoreToken = config.scoreToken || process.env.SCORE_TOKEN || ''
  app.locals.jwtSecret = crypto.randomBytes(32).toString('hex')
  app.locals.adminOverrideToken =
    config.adminOverrideToken || process.env.ADMIN_OVERRIDE_TOKEN || crypto.randomUUID()
  app.locals.directorySyncSecret =
    config.directorySyncSecret || process.env.DIRECTORY_SYNC_SECRET || crypto.randomUUID()
  app.locals.runtimeProofToken = crypto.randomBytes(16).toString('hex')
  global.__thornfieldRuntimeProofToken = app.locals.runtimeProofToken
  app.locals.port = config.port || Number(process.env.PORT) || 5000
  app.locals.oracleObservations = new Map()
  app.locals.webhookElevatedEmails = new Set()

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
