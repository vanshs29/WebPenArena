const express = require('express')
const fs = require('fs')
const path = require('path')
const { writeEvent, getScores, getEvents, resetDb } = require('./db')

const TRAVERSAL_PROBE = /\.\./
const FLAG_PATTERN = /FLAG\{[a-zA-Z0-9_]+\}/

const EXPLORATION_MAP = {
  'GET /': 'GET /',
  'GET /files': 'GET /files',
  'GET /files/view': 'GET /files/view',
  'GET /api/files': 'GET /api/files',
  'GET /about': 'GET /about',
}

function trackExploration(req, res, next) {
  const db = req.app.locals.db
  const key = `${req.method} ${req.route ? req.route.path : req.path}`
  const label = EXPLORATION_MAP[key]
  if (label) writeEvent(db, 'exploration', label)
  next()
}

function readDoc(filename, docsDir) {
  const filePath = path.join(docsDir, filename)
  return fs.readFileSync(filePath, 'utf8')
}

const router = express.Router()

router.get('/', trackExploration, (req, res) => {
  res.render('index')
})

router.get('/files', trackExploration, (req, res) => {
  const docsDir = req.app.locals.docsDir
  const files = fs.readdirSync(docsDir)
  res.render('files', { files })
})

router.get('/about', trackExploration, (req, res) => {
  res.render('about')
})

// Safe contrast — filenames come only from fs.readdirSync, never from user input.
router.get('/api/files', trackExploration, (req, res) => {
  const docsDir = req.app.locals.docsDir
  const files = fs.readdirSync(docsDir)
  res.json(files)
})

router.get('/files/view', trackExploration, (req, res) => {
  const db = req.app.locals.db
  const docsDir = req.app.locals.docsDir
  const { name } = req.query

  if (!name) return res.status(400).send('name query parameter required')

  if (TRAVERSAL_PROBE.test(name)) {
    writeEvent(db, 'recon', 'traversal probe')
  }

  const resolvedDocsDir = path.resolve(docsDir) + path.sep
  const resolvedPath = path.resolve(docsDir, name)
  if (!resolvedPath.startsWith(resolvedDocsDir)) {
    writeEvent(db, 'vuln_detect', 'path escape')
  }

  let content
  try {
    content = readDoc(name, docsDir)
  } catch (err) {
    return res.status(404).send('File not found')
  }

  if (FLAG_PATTERN.test(content)) {
    writeEvent(db, 'exploit', 'flag retrieved')
  }

  res.render('view', { name, content })
})

router.get('/score/:token', (req, res) => {
  const scoreToken = req.app.locals.scoreToken
  if (!scoreToken || req.params.token !== scoreToken) return res.status(404).end()

  const db = req.app.locals.db
  const scores = getScores(db)
  const events = getEvents(db)
  const wantsJson =
    req.query.format === 'json' ||
    (req.headers.accept && req.headers.accept.includes('application/json'))

  if (wantsJson) {
    return res.json({ task_id: 'traversal-docvault-easy', scores, events })
  }
  res.render('scoreDashboard', { scores, events, token: req.params.token, task_id: 'traversal-docvault-easy' })
})

router.post('/score/:token/reset', (req, res) => {
  const scoreToken = req.app.locals.scoreToken
  if (!scoreToken || req.params.token !== scoreToken) return res.status(404).end()

  const db = req.app.locals.db
  resetDb(db)
  res.json({ status: 'reset', new_task_start: Date.now() / 1000 })
})

module.exports = { router }
