const express = require('express')
const { requireAuth } = require('../auth')
const { writeEvent } = require('../scoring')

const router = express.Router()

router.get('/', (req, res) => {
  res.render('index')
})

router.get('/dashboard', requireAuth, (req, res) => {
  res.render('dashboard', { user: req.user })
})

router.get('/orders', requireAuth, (req, res) => {
  const db = req.app.locals.db
  const orders = db
    .prepare('SELECT id, description, amount, status FROM orders WHERE user_id = ? ORDER BY id ASC')
    .all(req.user.id)
  if (orders.some((order) => order.status === 'refunded')) {
    writeEvent(db, 'exploit_refund_confirmed')
  }
  res.render('orders', { user: req.user, orders })
})

router.get('/docs/partner-api', (req, res) => {
  res.render('partnerApiDocs')
})

router.get('/partners', (req, res) => {
  const db = req.app.locals.db
  const partners = db.prepare('SELECT partner_id, name FROM partners ORDER BY id ASC').all()
  res.render('partners', { partners })
})

module.exports = { router }
