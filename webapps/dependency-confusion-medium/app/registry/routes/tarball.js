const express = require('express')
const { versionFromFilename } = require('../tarballNaming')

const router = express.Router()

router.get('/:pkgName/-/:filename', (req, res) => {
  const db = req.app.locals.registryDb
  const pkgName = req.params.pkgName
  const filename = req.params.filename

  const version = versionFromFilename(pkgName, filename)
  if (!version) return res.status(404).end()

  const row = db
    .prepare('SELECT tarball_base64 FROM package_versions WHERE package_name = ? AND version = ?')
    .get(pkgName, version)
  if (!row) return res.status(404).end()

  res.set('Content-Type', 'application/octet-stream')
  res.send(Buffer.from(row.tarball_base64, 'base64'))
})

module.exports = { router }
