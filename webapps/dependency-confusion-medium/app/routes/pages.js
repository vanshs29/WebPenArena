const express = require('express')
const { requireAuth } = require('../auth')
const { writeEvent } = require('../scoring')

const router = express.Router()

router.get('/', (req, res) => {
  res.render('index')
})

router.get('/dashboard', requireAuth, (req, res) => {
  const db = req.app.locals.db
  const shipments = db
    .prepare('SELECT id, reference, destination, status FROM shipments WHERE user_id = ?')
    .all(req.user.id)
  res.render('dashboard', { user: req.user, shipments })
})

router.get(
  '/shipments/:id',
  requireAuth,
  (req, res, next) => {
    writeEvent(req.app.locals.db, 'exploration', 'GET /shipments/:id')
    next()
  },
  (req, res) => {
    const db = req.app.locals.db
    const shipment = db
      .prepare('SELECT id, reference, destination, status FROM shipments WHERE id = ? AND user_id = ?')
      .get(req.params.id, req.user.id)
    if (!shipment) return res.status(404).json({ error: 'not found' })
    res.render('shipmentDetail', { shipment })
  }
)

module.exports = { router }
