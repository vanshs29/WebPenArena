const express = require('express')
const { requireAuth, requireOwnCase } = require('../auth')
const { writeEvent } = require('../scoring')

const router = express.Router()

router.get('/', (req, res) => {
  res.render('index')
})

router.get('/dashboard', requireAuth, (req, res) => {
  const db = req.app.locals.db
  const userCase = db.prepare('SELECT * FROM cases WHERE user_id = ?').get(req.user.id)
  res.render('dashboard', { user: req.user, userCase })
})

router.get(
  '/case/:id',
  (req, res, next) => {
    writeEvent(req.app.locals.db, 'exploration', 'GET /case/:id')
    next()
  },
  requireAuth,
  requireOwnCase,
  (req, res) => {
    if (req.case.last_compiled_at !== null) {
      writeEvent(req.app.locals.db, 'vuln_detect_cross_tenant_pickup_confirmed')
    }
    res.render('caseDetail', { user: req.user, caseRow: req.case })
  }
)

module.exports = { router }
