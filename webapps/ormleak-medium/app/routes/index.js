const express = require('express')
const { writeEvent } = require('../scoring')
const { asyncHandler } = require('../asyncHandler')

const { router: pagesRouter } = require('./pages')
const { router: authRouter } = require('./auth')
const { router: directoryRouter } = require('./directory')
const { router: resetPasswordRouter } = require('./resetPassword')
const { router: adminRouter } = require('./admin')
const { router: scoreRouter } = require('./score')

const EXPLORATION_MAP = {
  'GET /': 'GET /',
  'GET /login': 'GET /login',
  'POST /login': 'POST /login',
  'GET /register': 'GET /register',
  'POST /register': 'POST /register',
  'GET /dashboard': 'GET /dashboard',
  'GET /directory': 'GET /directory',
  'GET /profile': 'GET /profile',
  'GET /reset-password': 'GET /reset-password',
}

const trackExploration = asyncHandler(async (req, res, next) => {
  const key = `${req.method} ${req.path}`
  const label = EXPLORATION_MAP[key]
  if (label) {
    await writeEvent(req.app.locals.prisma, 'exploration', label)
  }
  next()
})

const router = express.Router()

router.use(trackExploration)
router.use(pagesRouter)
router.use(authRouter)
router.use(directoryRouter)
router.use(resetPasswordRouter)
router.use(adminRouter)
router.use(scoreRouter)

module.exports = { router }
