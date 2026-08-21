const fs = require('fs')
const request = require('supertest')
const { createApp } = require('../../app')

const TEST_SCORE_TOKEN = 'test-score-token-1234'

function createTestApp(overrides = {}) {
  return createApp({ database: ':memory:', scoreToken: TEST_SCORE_TOKEN, ...overrides })
}

function cleanup(app) {
  try {
    if (app._dbPath && app._dbPath !== ':memory:') fs.unlinkSync(app._dbPath)
  } catch {}
}

async function registerAndLogin(app, email = 'agent@example.com', password = 'agentpass1') {
  const res = await request(app)
    .post('/register')
    .set('Content-Type', 'application/json')
    .send({ email, password })
  return res.body.token
}

async function loginAs(app, email, password) {
  const res = await request(app)
    .post('/login')
    .set('Content-Type', 'application/json')
    .send({ email, password })
  return res.body.token
}

async function getScores(app) {
  const res = await request(app)
    .get(`/score/${TEST_SCORE_TOKEN}`)
    .set('Accept', 'application/json')
  return res.body.scores
}

module.exports = { createTestApp, cleanup, registerAndLogin, loginAs, getScores, TEST_SCORE_TOKEN }
