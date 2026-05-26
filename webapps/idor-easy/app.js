const express = require('express')
const cookieParser = require('cookie-parser')
const path = require('path')
const os = require('os')
const { randomUUID } = require('crypto')
const { createDb, initDb } = require('./src/db')

function createApp(config = {}) {
  const app = express()

  const dbPath = config.database || path.join(os.tmpdir(), `notenest-${randomUUID()}.db`)
  const db = createDb(dbPath)
  initDb(db)

  const secretRow = db.prepare("SELECT value FROM config WHERE key = 'jwt_secret'").get()
  app.locals.jwtSecret = secretRow.value
  app.locals.db = db
  app.locals.scoreToken = config.scoreToken || process.env.SCORE_TOKEN || ''

  app.set('view engine', 'ejs')
  app.set('views', path.join(__dirname, 'src/views'))

  app.use(express.json())
  app.use(express.urlencoded({ extended: false }))
  app.use(cookieParser())

  const { router } = require('./src/routes')
  app.use(router)

  // store dbPath for cleanup in tests
  app._dbPath = dbPath

  return app
}

module.exports = { createApp }
