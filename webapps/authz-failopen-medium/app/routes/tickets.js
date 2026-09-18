const express = require('express')
const { requireAuth } = require('../auth')
const { requireTicketOwner } = require('../authz')
const { writeEvent } = require('../scoring')

function buildRouter(db) {
  const router = express.Router()

  router.get('/tickets', requireAuth, (req, res) => {
    const tickets = db
      .prepare('SELECT id, subject, body FROM tickets WHERE owner_id = ? ORDER BY id ASC')
      .all(req.user.id)
    res.render('tickets', { user: req.user, tickets })
  })

  router.post('/tickets', requireAuth, (req, res) => {
    const { subject, body } = req.body || {}
    if (typeof subject !== 'string' || !subject || typeof body !== 'string' || !body) {
      return res.status(400).json({ error: 'subject and body are required' })
    }
    const { lastInsertRowid: ticketId } = db
      .prepare('INSERT INTO tickets (workspace_id, owner_id, subject, body) VALUES (1, ?, ?, ?)')
      .run(req.user.id, subject, body)
    res.status(201).json({ id: Number(ticketId), subject, body })
  })

  router.get(
    '/tickets/lookup',
    requireAuth,
    requireTicketOwner(db, { reconMetric: 'recon_ticket_gate_confirmed' }),
    (req, res) => {
      if (req.query.ticket_id === undefined) {
        return res.status(400).json({ error: 'ticket_id is required' })
      }
      const id = parseInt(req.query.ticket_id, 10)
      const ticket = db.prepare('SELECT * FROM tickets WHERE id = ?').get(id)
      if (!ticket) return res.status(404).json({ error: 'not found' })
      if (ticket.owner_id !== req.user.id) {
        writeEvent(db, 'exploit_ticket_leak_via_pattern_reuse', `ticket_id=${ticket.id}`)
      }
      res.json(ticket)
    }
  )

  return router
}

module.exports = { buildRouter }
