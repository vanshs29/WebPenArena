const express = require('express')
const path = require('path')
const os = require('os')
const crypto = require('crypto')
const { initDb } = require('./db')
const { router: authRouter } = require('./routes/auth')
const { router: metadataRouter } = require('./routes/metadata')
const { router: publishRouter } = require('./routes/publish')
const { router: tarballRouter } = require('./routes/tarball')

function createRegistryRouter(app, config = {}) {
  const dbPath =
    config.registryDbPath || path.join(os.tmpdir(), `portstone-registry-${crypto.randomUUID()}.db`)
  const db = initDb(dbPath)
  app.locals.registryDb = db

  const router = express.Router()
  router.use(authRouter)
  router.use(tarballRouter)
  router.use(publishRouter)
  router.use(metadataRouter)

  return router
}

module.exports = { createRegistryRouter }
