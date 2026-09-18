const request = require('supertest')
const fs = require('fs')
const os = require('os')
const path = require('path')
const crypto = require('crypto')
const { createApp } = require('../app')

const TEST_SCORE_TOKEN = 'test-score-token-fixed'
const TEST_ARCHIVE_API_KEY = 'test-archive-api-key-fixed'

function newTestApp(overrides = {}) {
  const scratchRoot = fs.mkdtempSync(path.join(os.tmpdir(), `ashwell-test-${crypto.randomUUID()}-`))
  const app = createApp({
    dbPath: ':memory:',
    scoreToken: TEST_SCORE_TOKEN,
    internalArchiveApiKey: TEST_ARCHIVE_API_KEY,
    uploadsRoot: path.join(scratchRoot, 'uploads'),
    archiveRoot: path.join(scratchRoot, 'archives'),
    ...overrides,
  })
  app.locals.scratchRoot = scratchRoot
  return app
}

async function registerUser(app, { username = 'alice', email = 'alice@test.local', password = 'password123' } = {}) {
  return request(app).post('/register').send({ username, email, password })
}

async function loginUser(app, email = 'alice@test.local', password = 'password123') {
  return request(app).post('/login').send({ email, password })
}

async function registerAndLogin(app, email = 'alice@test.local', password = 'password123') {
  await registerUser(app, { email, password, username: email.split('@')[0] })
  const res = await loginUser(app, email, password)
  return res.headers['set-cookie'][0].split(';')[0]
}

function getCaseIdForEmail(app, email) {
  const db = app.locals.db
  const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email)
  const caseRow = db.prepare('SELECT id FROM cases WHERE user_id = ?').get(user.id)
  return caseRow.id
}

async function uploadDocument(app, cookie, caseId, filename, content = 'x') {
  return request(app).post(`/case/${caseId}/documents`).set('Cookie', cookie).send({ filename, content })
}

async function listDocuments(app, cookie, caseId) {
  return request(app).get(`/case/${caseId}/documents`).set('Cookie', cookie)
}

async function getScoreBody(app, token = TEST_SCORE_TOKEN) {
  const res = await request(app).get(`/score/${token}`).set('Accept', 'application/json')
  return res.body
}

async function getScores(app, token = TEST_SCORE_TOKEN) {
  const body = await getScoreBody(app, token)
  return body.scores
}

module.exports = {
  newTestApp,
  registerUser,
  loginUser,
  registerAndLogin,
  getCaseIdForEmail,
  uploadDocument,
  listDocuments,
  getScoreBody,
  getScores,
  TEST_SCORE_TOKEN,
  TEST_ARCHIVE_API_KEY,
}
