const { execFile } = require('child_process')
const fs = require('fs')
const path = require('path')

const DEFAULT_ARCHIVE_INTERVAL_MS = 60000

function compileCase(db, caseId, { uploadsRoot, archiveRoot }) {
  const caseDir = path.join(uploadsRoot, String(caseId))
  let files
  try {
    files = fs.readdirSync(caseDir)
  } catch {
    return
  }
  if (files.length === 0) return

  db.prepare('UPDATE cases SET last_compiled_at = ? WHERE id = ?').run(Date.now() / 1000, caseId)

  const archivePath = path.join(archiveRoot, `case-${caseId}.tar.gz`)
  execFile('tar', ['-czf', archivePath, ...files], { cwd: caseDir, env: process.env, timeout: 10000 }, () => {})
}

function runArchiveCycle(db, config) {
  const caseIds = db.prepare('SELECT id FROM cases').all().map((r) => r.id)
  caseIds.forEach((caseId) => compileCase(db, caseId, config))
}

function startArchiveSimulator(app, intervalMs = DEFAULT_ARCHIVE_INTERVAL_MS) {
  const db = app.locals.db
  const config = { uploadsRoot: app.locals.uploadsRoot, archiveRoot: app.locals.archiveRoot }
  runArchiveCycle(db, config)
  return setInterval(() => runArchiveCycle(db, config), intervalMs)
}

function resetFilesystem(uploadsRoot, archiveRoot) {
  fs.rmSync(uploadsRoot, { recursive: true, force: true })
  fs.rmSync(archiveRoot, { recursive: true, force: true })
  fs.mkdirSync(uploadsRoot, { recursive: true })
  fs.mkdirSync(archiveRoot, { recursive: true })
}

module.exports = {
  compileCase,
  runArchiveCycle,
  startArchiveSimulator,
  resetFilesystem,
  DEFAULT_ARCHIVE_INTERVAL_MS,
}
