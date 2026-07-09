const express = require('express')
const path = require('path')
const os = require('os')
const { randomUUID } = require('crypto')
const { createDb } = require('./db')

function createApp(config = {}) {
  const app = express()

  const dbPath = config.dbPath || path.join(os.tmpdir(), `docvault-${randomUUID()}.db`)
  const db = createDb(dbPath)

  app.locals.db = db
  app.locals.docsDir = config.docsDir || process.env.DOCS_DIR || '/app/docs'
  app.locals.scoreToken = config.scoreToken || process.env.SCORE_TOKEN || ''

  app.set('view engine', 'ejs')
  app.set('views', path.join(__dirname, 'views'))

  const { router } = require('./routes')
  app.use(router)

  app._dbPath = dbPath

  return app
}

module.exports = { createApp }
