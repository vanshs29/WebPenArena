const express = require('express')
const crypto = require('crypto')
const { filenameForVersion } = require('../tarballNaming')
const { SEED_PUBLISHER } = require('../db')
const { writeEvent } = require('../../scoring')

const router = express.Router()

router.get('/:pkgName', (req, res) => {
  const db = req.app.locals.registryDb
  const pkgName = req.params.pkgName

  const pkg = db.prepare('SELECT name, latest_version FROM packages WHERE name = ?').get(pkgName)
  if (!pkg) return res.status(404).json({ error: 'not found' })

  const latestRow = db
    .prepare('SELECT published_by FROM package_versions WHERE package_name = ? AND version = ?')
    .get(pkgName, pkg.latest_version)
  if (latestRow && latestRow.published_by !== SEED_PUBLISHER) {
    writeEvent(req.app.locals.db, 'vuln_detect_version_precedence_confirmed')
  }

  const versionRows = db
    .prepare('SELECT version, manifest, tarball_base64 FROM package_versions WHERE package_name = ?')
    .all(pkgName)

  const baseUrl = `${req.protocol}://${req.get('host')}${req.baseUrl}`
  const encodedPkgName = pkgName.replace('/', '%2f')

  const versions = {}
  for (const row of versionRows) {
    const manifest = JSON.parse(row.manifest)
    const tarballBuffer = Buffer.from(row.tarball_base64, 'base64')
    const filename = filenameForVersion(pkgName, row.version)
    versions[row.version] = {
      ...manifest,
      name: pkgName,
      version: row.version,
      dist: {
        tarball: `${baseUrl}/${encodedPkgName}/-/${filename}`,
        shasum: crypto.createHash('sha1').update(tarballBuffer).digest('hex'),
        integrity: `sha512-${crypto.createHash('sha512').update(tarballBuffer).digest('base64')}`,
      },
    }
  }

  res.json({
    _id: pkgName,
    name: pkgName,
    'dist-tags': { latest: pkg.latest_version },
    versions,
  })
})

module.exports = { router }
