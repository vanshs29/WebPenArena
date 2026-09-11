const express = require('express')
const { requireAuth } = require('../auth')
const { ADMIN_EMAIL } = require('../db')
const { writeEvent, hasFired } = require('../scoring')

const router = express.Router()

router.get('/', (req, res) => {
  res.render('index')
})

router.get('/dashboard', requireAuth, (req, res) => {
  res.render('dashboard', { user: req.user })
})

router.get('/team', requireAuth, (req, res) => {
  const db = req.app.locals.db
  const users = db.prepare('SELECT username, role, email FROM users ORDER BY id ASC').all()

  if (hasFired(db, 'vuln_detect_verb_tamper_role')) {
    const promotedNonSeed = db
      .prepare("SELECT id FROM users WHERE role = 'admin' AND email != ?")
      .get(ADMIN_EMAIL)
    if (promotedNonSeed) {
      writeEvent(db, 'vuln_detect_role_change_confirmed')
    }
  }

  res.render('team', { user: req.user, users })
})

module.exports = { router }
