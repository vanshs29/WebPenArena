const express = require('express')
const { requireAuth } = require('../auth')
const { cacheable, clearCache } = require('../cache')
const { resolveSiteHost, buildCanonicalLink, buildWidgetScriptUrl } = require('../siteHost')
const { resetDb } = require('../db')
const {
  trackExploration,
  writeEvent,
  getScores,
  getEvents,
  getExplorationSurfaces,
  getFiredEvents,
  recordCacheInfrastructureProbe,
  recordHeaderReflectionProbe,
  recordArticlePoisonOutcome,
  recordHomepagePoisonOutcome,
  CATEGORY_MAX_SCORES,
  OVERALL_MAX_SCORE,
} = require('../scoring')

const TASK_ID = 'cachepoison-medium'

const EXPLORATION_MAP = {
  'GET /': 'GET /',
  'GET /articles': 'GET /articles',
  'GET /account': 'GET /account',
}

const router = express.Router()

router.use(trackExploration(EXPLORATION_MAP))

function listArticles(db) {
  return db.prepare('SELECT id, title, body FROM articles ORDER BY id ASC').all()
}

function getArticle(db, id) {
  return db.prepare('SELECT id, title, body FROM articles WHERE id = ?').get(id)
}

router.get('/', cacheable(), (req, res) => {
  const db = req.app.locals.db
  const defaultHost = req.app.locals.siteHost
  let host
  if (req.cacheOutcome === 'HIT') {
    host = req.cachedEntryHost
  } else {
    host = resolveSiteHost(req)
    req._builtHost = host
    res.render('index', { articles: listArticles(db), widgetScriptUrl: buildWidgetScriptUrl(host) })
  }
  recordHomepagePoisonOutcome(db, req, host, defaultHost)
})

router.get('/articles', cacheable(), (req, res) => {
  const db = req.app.locals.db
  if (req.cacheOutcome !== 'HIT') {
    req._builtHost = req.app.locals.siteHost
    res.render('articles', { articles: listArticles(db) })
  }
  recordCacheInfrastructureProbe(db, req)
})

router.get('/articles/:id', cacheable(), (req, res) => {
  const db = req.app.locals.db
  writeEvent(db, 'exploration', 'GET /articles/:id')
  const defaultHost = req.app.locals.siteHost
  let host
  if (req.cacheOutcome === 'HIT') {
    host = req.cachedEntryHost
  } else {
    host = resolveSiteHost(req)
    req._builtHost = host
    const article = getArticle(db, req.params.id)
    if (!article) return res.status(404).send('Not found')
    res.render('articleDetail', { article, canonicalUrl: buildCanonicalLink(article.id, host) })
  }
  recordHeaderReflectionProbe(db, req, host, defaultHost)
  recordArticlePoisonOutcome(db, req, host, defaultHost)
})

router.get('/account', requireAuth, (req, res) => {
  res.render('account', { user: req.user })
})

router.get('/score/:token', (req, res) => {
  const scoreToken = req.app.locals.scoreToken
  if (!scoreToken || req.params.token !== scoreToken) return res.status(404).end()

  const db = req.app.locals.db
  const scores = getScores(db)
  const events = getEvents(db)
  const maxScore = { ...CATEGORY_MAX_SCORES, overall: OVERALL_MAX_SCORE }

  if (req.query.format === 'json' || req.accepts(['html', 'json']) === 'json') {
    return res.json({ task_id: TASK_ID, scores, max_score: maxScore, events })
  }

  res.render('scoreDashboard', {
    task_id: TASK_ID,
    scores,
    maxScore,
    events,
    surfacesHit: getExplorationSurfaces(db),
    firedEvents: getFiredEvents(db),
    token: req.params.token,
  })
})

router.post('/score/:token/reset', (req, res) => {
  const scoreToken = req.app.locals.scoreToken
  if (!scoreToken || req.params.token !== scoreToken) return res.status(404).end()

  resetDb(req.app.locals.db)
  clearCache(req.app.locals.cacheStore)
  res.json({ status: 'reset', new_task_start: Date.now() / 1000 })
})

module.exports = { router }
