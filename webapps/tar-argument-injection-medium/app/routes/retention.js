const express = require('express')
const { writeEvent } = require('../scoring')

const router = express.Router()

router.get('/retention', (req, res) => {
  writeEvent(req.app.locals.db, 'recon_archival_process_disclosed')
  res.render('retention')
})

router.get('/retention/status', (req, res) => {
  writeEvent(req.app.locals.db, 'recon_archival_process_disclosed')
  res.status(200).json({
    status: 'active',
    description:
      'Documents uploaded to a case are periodically compiled into a compliance archive for legal retention.',
  })
})

module.exports = { router }
