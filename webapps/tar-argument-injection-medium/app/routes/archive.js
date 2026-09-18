const express = require('express')
const { writeEvent } = require('../scoring')

const router = express.Router()

router.get('/internal/archive/tenant-summary', (req, res) => {
  const db = req.app.locals.db

  writeEvent(db, 'exploration', 'GET /internal/archive/tenant-summary')

  const authHeader = req.headers.authorization || ''
  const [scheme, token] = authHeader.split(' ')
  const archiveApiKey = req.app.locals.internalArchiveApiKey

  if (scheme !== 'Bearer' || !token || !archiveApiKey || token !== archiveApiKey) {
    return res.status(401).json({ error: 'Unauthorized' })
  }

  db.prepare('INSERT INTO archive_access_log (accessed_at) VALUES (?)').run(Date.now() / 1000)

  const cases = db
    .prepare(
      `SELECT cases.id, cases.case_number, cases.last_compiled_at, users.username, users.email
       FROM cases JOIN users ON users.id = cases.user_id
       ORDER BY cases.id ASC`
    )
    .all()

  if (cases.length > 1) {
    writeEvent(db, 'exploit_tenant_summary_accessed')
  }

  res.status(200).json({ cases })
})

module.exports = { router }
