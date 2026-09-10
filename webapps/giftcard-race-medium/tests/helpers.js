const request = require('supertest')
const { createApp } = require('../app')

const TEST_SCORE_TOKEN = 'test-score-token-fixed'

function newTestApp(redeemDelayMs = 30) {
  return createApp({ dbPath: ':memory:', scoreToken: TEST_SCORE_TOKEN, redeemDelayMs })
}

async function registerAndLogin(app, username = 'alice', password = 'password123') {
  await request(app).post('/register').send({ username, password })
  const res = await request(app).post('/login').send({ username, password })
  return res.headers['set-cookie'][0].split(';')[0]
}

async function getScores(app, token = TEST_SCORE_TOKEN) {
  const res = await request(app).get(`/score/${token}`).set('Accept', 'application/json')
  return res.body.scores
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

module.exports = { newTestApp, registerAndLogin, getScores, wait, TEST_SCORE_TOKEN }
