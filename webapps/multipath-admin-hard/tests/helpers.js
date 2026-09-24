const request = require('supertest')
const { createApp } = require('../app')
const { PLATFORM_ADMIN_EMAIL } = require('../db/seed')

const TEST_SCORE_TOKEN = 'test-score-token-fixed'
const TEST_ADMIN_OVERRIDE_TOKEN = 'test-override-token-fixed'
const TEST_DIRECTORY_SYNC_SECRET = 'test-sync-secret-fixed'

function newTestApp(overrides = {}) {
  return createApp({
    dbPath: ':memory:',
    scoreToken: TEST_SCORE_TOKEN,
    adminOverrideToken: TEST_ADMIN_OVERRIDE_TOKEN,
    directorySyncSecret: TEST_DIRECTORY_SYNC_SECRET,
    ...overrides,
  })
}

async function registerUser(app, { workspaceName, email, password = 'password123' }) {
  return request(app).post('/register').send({ workspaceName, email, password })
}

async function loginUser(app, email, password = 'password123') {
  return request(app).post('/login').send({ email, password })
}

function cookieFrom(res) {
  return res.headers['set-cookie'][0].split(';')[0]
}

async function registerAndLogin(app, { workspaceName, email, password = 'password123' }) {
  await registerUser(app, { workspaceName, email, password })
  const res = await loginUser(app, email, password)
  return cookieFrom(res)
}

function getPlatformAdminPassword(app) {
  const row = app.locals.db.prepare('SELECT password FROM users WHERE email = ?').get(PLATFORM_ADMIN_EMAIL)
  return row.password
}

async function loginAsPlatformAdmin(app) {
  const password = getPlatformAdminPassword(app)
  const res = await loginUser(app, PLATFORM_ADMIN_EMAIL, password)
  return cookieFrom(res)
}

async function getScoreBody(app, token = TEST_SCORE_TOKEN) {
  const res = await request(app).get(`/score/${token}`).set('Accept', 'application/json')
  return res.body
}

async function getScores(app, token = TEST_SCORE_TOKEN) {
  const body = await getScoreBody(app, token)
  return body.scores
}

function withLiveServer(app, fn) {
  return new Promise((resolve, reject) => {
    const server = app.listen(0, async () => {
      app.locals.port = server.address().port
      try {
        await fn()
        resolve()
      } catch (err) {
        reject(err)
      } finally {
        server.close()
      }
    })
  })
}

module.exports = {
  newTestApp,
  registerUser,
  loginUser,
  registerAndLogin,
  cookieFrom,
  getPlatformAdminPassword,
  loginAsPlatformAdmin,
  getScoreBody,
  getScores,
  withLiveServer,
  TEST_SCORE_TOKEN,
  TEST_ADMIN_OVERRIDE_TOKEN,
  TEST_DIRECTORY_SYNC_SECRET,
  PLATFORM_ADMIN_EMAIL,
}
