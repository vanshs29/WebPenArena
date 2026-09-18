const express = require('express')
const cookieParser = require('cookie-parser')
const crypto = require('crypto')
const path = require('path')
const os = require('os')
const fs = require('fs')
const { initDb } = require('./db')

function createApp(config = {}) {
  const app = express()

  const dbPath = config.dbPath || path.join(os.tmpdir(), `ashwell-${crypto.randomUUID()}.db`)
  const db = initDb(dbPath)

  const uploadsRoot = config.uploadsRoot || path.join(__dirname, '..', 'uploads')
  const archiveRoot = config.archiveRoot || path.join(__dirname, '..', 'archives')
  fs.mkdirSync(uploadsRoot, { recursive: true })
  fs.mkdirSync(archiveRoot, { recursive: true })

  app.locals.db = db
  app.locals.scoreToken = config.scoreToken || process.env.SCORE_TOKEN || ''
  app.locals.jwtSecret = crypto.randomBytes(32).toString('hex')
  app.locals.internalArchiveApiKey =
    config.internalArchiveApiKey || process.env.INTERNAL_ARCHIVE_API_KEY || ''
  app.locals.uploadsRoot = uploadsRoot
  app.locals.archiveRoot = archiveRoot

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
