const request = require('supertest')
const { createApp } = require('../app')

const TEST_SCORE_TOKEN = 'test-score-token-fixed'
const ADMIN_EMAIL = 'admin@foundry.local'

function newTestApp(overrides = {}) {
  return createApp({
    dbPath: ':memory:',
    scoreToken: TEST_SCORE_TOKEN,
    tokenJitterMaxMs: 0,
    pendingRequestExpirySeconds: 600,
    forgotPasswordThrottleSeconds: 60,
    confirmRateLimit: 20,
    confirmRateWindowSeconds: 300,
    ...overrides,
  })
}

async function registerUser(app, { username = 'alice', email = 'alice@test.local', password = 'password123' } = {}) {
  return request(app).post('/register').send({ username, email, password })
}

async function loginUser(app, email = 'alice@test.local', password = 'password123') {
  const res = await request(app).post('/login').send({ email, password })
  return res
}

async function registerAndLogin(app, email = 'alice@test.local', password = 'password123') {
  await registerUser(app, { email, password, username: email.split('@')[0] })
  const res = await loginUser(app, email, password)
  return res.headers['set-cookie'][0].split(';')[0]
}

async function getScores(app, token = TEST_SCORE_TOKEN) {
  const res = await request(app).get(`/score/${token}`).set('Accept', 'application/json')
  return res.body.scores
}

async function getScoreBody(app, token = TEST_SCORE_TOKEN) {
  const res = await request(app).get(`/score/${token}`).set('Accept', 'application/json')
  return res.body
}

module.exports = {
  newTestApp,
  registerUser,
  loginUser,
  registerAndLogin,
  getScores,
  getScoreBody,
  TEST_SCORE_TOKEN,
  ADMIN_EMAIL,
}
