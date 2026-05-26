const { createApp } = require('../app')
const request = require('supertest')
const fs = require('fs')

const TEST_SCORE_TOKEN = 'test-score-token-1234'

function createTestApp() {
  const app = createApp({ scoreToken: TEST_SCORE_TOKEN })
  return app
}

function cleanup(app) {
  try {
    if (app._dbPath) fs.unlinkSync(app._dbPath)
  } catch {}
}

async function registerAndLogin(app, email = 'test@example.com', password = 'testpass') {
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
  return res.body
}

module.exports = { createTestApp, cleanup, registerAndLogin, loginAs, getScores, TEST_SCORE_TOKEN }
