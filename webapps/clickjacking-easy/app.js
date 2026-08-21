const express = require('express')
const cookieParser = require('cookie-parser')
const path = require('path')
const os = require('os')
const { randomUUID } = require('crypto')
const { createDb, getJwtSecret } = require('./src/db')
const { frameProtection } = require('./src/frameProtection')

function createApp(config = {}) {
  const app = express()

  const dbPath = config.database || path.join(os.tmpdir(), `billfold-${randomUUID()}.db`)
  const db = createDb(dbPath, config.jwtSecret)

  app.locals.db = db
  app.locals.jwtSecret = getJwtSecret(db)
  app.locals.scoreToken = config.scoreToken || process.env.SCORE_TOKEN || ''

  app.set('view engine', 'ejs')
  app.set('views', path.join(__dirname, 'src/views'))

  app.use(cookieParser())
  app.use(express.json())
  app.use(express.urlencoded({ extended: false }))

  // The account router is mounted before frameProtection is applied, so its
  // routes never pass through that middleware — see src/frameProtection.js.
  const { router: accountRouter } = require('./src/routes/account')
  app.use('/account', accountRouter)

  app.use(frameProtection)

  const { router: mainRouter } = require('./src/routes/main')
  app.use('/', mainRouter)

  app._dbPath = dbPath

  return app
}

module.exports = { createApp }
