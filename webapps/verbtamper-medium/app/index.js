const express = require('express')
const cookieParser = require('cookie-parser')
const path = require('path')
const os = require('os')
const crypto = require('crypto')
const { initDb } = require('./db')

function createApp(config = {}) {
  const app = express()

  const dbPath =
    config.dbPath || path.join(os.tmpdir(), `wrenlake-${crypto.randomUUID()}.db`)
  const { db, seed } = initDb(dbPath)

  app.locals.db = db
  app.locals.scoreToken = config.scoreToken || process.env.SCORE_TOKEN || ''
  app.locals.jwtSecret = crypto.randomBytes(32).toString('hex')
  app.locals.seedAdminPassword = seed.adminPassword

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
