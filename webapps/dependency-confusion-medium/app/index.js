const express = require('express')
const cookieParser = require('cookie-parser')
const crypto = require('crypto')
const path = require('path')
const os = require('os')
const { initDb } = require('./db')
const { createRegistryRouter } = require('./registry')

function createApp(config = {}) {
  const app = express()

  const dbPath = config.dbPath || path.join(os.tmpdir(), `portstone-${crypto.randomUUID()}.db`)
  const db = initDb(dbPath)

  app.locals.db = db
  app.locals.scoreToken = config.scoreToken || process.env.SCORE_TOKEN || ''
  app.locals.jwtSecret = crypto.randomBytes(32).toString('hex')
  app.locals.internalBillingApiKey =
    config.internalBillingApiKey || process.env.INTERNAL_BILLING_API_KEY || ''

  app.set('view engine', 'ejs')
  app.set('views', path.join(__dirname, 'views'))

  app.use(express.json({ limit: '10mb' }))
  app.use(express.urlencoded({ extended: true }))
  app.use(cookieParser())

  const registryRouter = createRegistryRouter(app, { registryDbPath: config.registryDbPath })
  app.use('/registry', registryRouter)

  const { router } = require('./routes')
  app.use(router)

  return app
}

module.exports = { createApp }
