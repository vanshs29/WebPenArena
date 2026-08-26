const express = require('express')
const cookieParser = require('cookie-parser')
const path = require('path')
const os = require('os')
const fs = require('fs')
const { randomUUID } = require('crypto')
const { createDb } = require('./db')
const { loadConfig } = require('./config')
const { seedDataFiles } = require('./seedFiles')

function createApp(config = {}) {
  const app = express()

  const dataDir = config.dataDir || fs.mkdtempSync(path.join(os.tmpdir(), 'ledger-'))
  const uploadsDir = path.join(dataDir, 'uploads')
  const configDir = path.join(dataDir, 'config')
  seedDataFiles(uploadsDir, configDir)

  const { jwtSecret } = loadConfig(configDir)

  const dbPath = config.dbPath || path.join(os.tmpdir(), `ledger-${randomUUID()}.db`)
  const db = createDb(dbPath)

  app.locals.db = db
  app.locals.scoreToken = config.scoreToken || process.env.SCORE_TOKEN || ''
  app.locals.jwtSecret = jwtSecret
  app.locals.uploadsDir = uploadsDir
  app.locals.configDir = configDir

  app.set('view engine', 'ejs')
  app.set('views', path.join(__dirname, 'views'))

  app.use(express.json())
  app.use(express.urlencoded({ extended: true }))
  app.use(cookieParser())

  const { router } = require('./routes')
  app.use(router)

  app._dbPath = dbPath

  return app
}

module.exports = { createApp }
