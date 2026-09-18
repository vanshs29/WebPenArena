const express = require('express')
const fs = require('fs')
const path = require('path')
const { requireAuth, requireOwnCase } = require('../auth')
const { writeEvent } = require('../scoring')

const router = express.Router()

const FLAG_FILENAMES = ['--checkpoint=1', '--checkpoint-action=exec=sh shell.sh', 'shell.sh']

function sanitizeFilename(name) {
  if (typeof name !== 'string' || name.length === 0) return null
  if (name.includes('/') || name.includes('\\') || name.includes('..')) return null
  return name
}

router.post(
  '/case/:id/documents',
  (req, res, next) => {
    writeEvent(req.app.locals.db, 'exploration', 'POST /case/:id/documents')
    next()
  },
  requireAuth,
  requireOwnCase,
  (req, res) => {
    const filename = sanitizeFilename(req.body.filename)
    if (!filename) return res.status(400).json({ error: 'invalid filename' })

    const db = req.app.locals.db
    const caseDir = path.join(req.app.locals.uploadsRoot, String(req.case.id))
    fs.mkdirSync(caseDir, { recursive: true })
    fs.writeFileSync(path.join(caseDir, filename), req.body.content || '')

    db.prepare('INSERT INTO documents (case_id, filename, content) VALUES (?, ?, ?)').run(
      req.case.id,
      filename,
      req.body.content || ''
    )

    res.status(201).json({ ok: true, filename })
  }
)

router.get(
  '/case/:id/documents',
  (req, res, next) => {
    writeEvent(req.app.locals.db, 'exploration', 'GET /case/:id/documents')
    next()
  },
  requireAuth,
  requireOwnCase,
  (req, res) => {
    const db = req.app.locals.db
    const documents = db
      .prepare('SELECT filename FROM documents WHERE case_id = ? ORDER BY id ASC')
      .all(req.case.id)
    const filenames = documents.map((d) => d.filename)

    if (filenames.some((f) => f.startsWith('-'))) {
      writeEvent(db, 'recon_dash_filename_accepted')
    }

    if (FLAG_FILENAMES.every((f) => filenames.includes(f))) {
      writeEvent(db, 'vuln_detect_flag_files_planted', `case_id=${req.case.id}`)
    }

    res.status(200).json({ documents: filenames })
  }
)

module.exports = { router, sanitizeFilename, FLAG_FILENAMES }
