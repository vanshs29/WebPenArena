const request = require('supertest')
const { createApp } = require('../app')

const TEST_SCORE_TOKEN = 'test-score-token-fixed'

function newTestApp() {
  return createApp({ dbPath: ':memory:', scoreToken: TEST_SCORE_TOKEN, siteHost: 'northwire.local' })
}

async function registerAndLogin(app, email = 'alice@test.local', password = 'password123') {
  await request(app).post('/register').send({ username: 'alice', email, password })
  const res = await request(app).post('/login').send({ email, password })
  return res.headers['set-cookie'][0].split(';')[0]
}

async function getScores(app, token = TEST_SCORE_TOKEN) {
  const res = await request(app).get(`/score/${token}`).set('Accept', 'application/json')
  return res.body.scores
}

module.exports = { newTestApp, registerAndLogin, getScores, TEST_SCORE_TOKEN }
