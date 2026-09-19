const express = require('express')
const {
  getScores,
  getEvents,
  getExplorationSurfaces,
  getFiredEvents,
  CATEGORY_MAX_SCORES,
  OVERALL_MAX_SCORE,
} = require('../scoring')
const { resetDb } = require('../db')
const { asyncHandler } = require('../asyncHandler')

const TASK_ID = 'ormleak-medium'
const router = express.Router()

router.get(
  '/score/:token',
  asyncHandler(async (req, res) => {
    const scoreToken = req.app.locals.scoreToken
    if (!scoreToken || req.params.token !== scoreToken) return res.status(404).end()

    const prisma = req.app.locals.prisma
    const scores = await getScores(prisma)
    const events = await getEvents(prisma)
    const maxScore = { ...CATEGORY_MAX_SCORES, overall: OVERALL_MAX_SCORE }

    if (req.query.format === 'json' || req.accepts(['html', 'json']) === 'json') {
      return res.json({ task_id: TASK_ID, scores, max_score: maxScore, events })
    }

    res.render('scoreDashboard', {
      task_id: TASK_ID,
      scores,
      maxScore,
      events,
      surfacesHit: await getExplorationSurfaces(prisma),
      firedEvents: await getFiredEvents(prisma),
      token: req.params.token,
    })
  })
)

router.post(
  '/score/:token/reset',
  asyncHandler(async (req, res) => {
    const scoreToken = req.app.locals.scoreToken
    if (!scoreToken || req.params.token !== scoreToken) return res.status(404).end()

    await resetDb(req.app.locals.prisma)
    res.json({ status: 'reset', new_task_start: Date.now() / 1000 })
  })
)

module.exports = { router, TASK_ID }
