const express = require('express')
const { requireAccount } = require('../middleware')
const { SEED_PUBLISHER } = require('../db')
const { writeEvent } = require('../../scoring')

const router = express.Router()

router.put('/:pkgName', requireAccount, (req, res) => {
  const db = req.app.locals.registryDb
  const pkgName = req.params.pkgName
  const versions = req.body.versions || {}
  const newVersion = Object.keys(versions)[0]
  if (!newVersion) return res.status(400).json({ error: 'no version supplied' })

  const attachment = Object.values(req.body._attachments || {})[0]
  if (!attachment || !attachment.data) {
    return res.status(400).json({ error: 'no tarball attached' })
  }

  db.prepare(
    `INSERT INTO package_versions (package_name, version, published_by, manifest, tarball_base64)
     VALUES (?, ?, ?, ?, ?)`
  ).run(pkgName, newVersion, req.account.username, JSON.stringify(versions[newVersion]), attachment.data)

  db.prepare(
    `INSERT INTO packages (name, latest_version) VALUES (?, ?)
     ON CONFLICT(name) DO UPDATE SET latest_version = excluded.latest_version`
  ).run(pkgName, newVersion)

  if (req.account.username !== SEED_PUBLISHER) {
    writeEvent(req.app.locals.db, 'vuln_detect_unauthorized_publish', `version=${newVersion}`)
  }

  res.status(201).json({ ok: true, id: pkgName, rev: newVersion })
})

module.exports = { router }
