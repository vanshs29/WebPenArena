const express = require('express')
const cookieParser = require('cookie-parser')
const path = require('path')
const os = require('os')
const crypto = require('crypto')
const { initDb } = require('./db')
const { createCacheStore } = require('./cache')

function createApp(config = {}) {
  const app = express()

  const dbPath =
    config.dbPath || path.join(os.tmpdir(), `northwire-${crypto.randomUUID()}.db`)
  const db = initDb(dbPath)

  app.locals.db = db
  app.locals.cacheStore = createCacheStore()
  app.locals.scoreToken = config.scoreToken || process.env.SCORE_TOKEN || ''
  app.locals.siteHost = config.siteHost || process.env.SITE_HOST || 'northwire.local'
  app.locals.jwtSecret = crypto.randomBytes(32).toString('hex')

  app.set('view engine', 'ejs')
  app.set('views', path.join(__dirname, 'views'))

  app.use(express.json())
  app.use(express.urlencoded({ extended: true }))
  app.use(cookieParser())

  const { router: authRouter } = require('./routes/auth')
  const { router: pagesRouter } = require('./routes/pages')
  app.use(authRouter)
  app.use(pagesRouter)

  return app
}

module.exports = { createApp }
