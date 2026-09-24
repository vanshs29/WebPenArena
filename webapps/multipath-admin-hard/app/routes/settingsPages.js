const express = require('express')
const { requireAuth } = require('../auth')
const { writeEvent } = require('../scoring')

const router = express.Router()

router.get('/settings/directory-sync', requireAuth, (req, res) => {
  const secret = req.app.locals.directorySyncSecret
  const db = req.app.locals.db
  if (req.user.role === 'member') {
    writeEvent(db, 'recon_directory_sync_page_ungated')
    writeEvent(db, 'recon_sync_secret_disclosed')
  }
  res.render('settingsDirectorySync', { syncSecret: secret })
})

module.exports = { router }
