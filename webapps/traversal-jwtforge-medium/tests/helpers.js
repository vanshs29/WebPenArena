const request = require('supertest')
const jwt = require('jsonwebtoken')
const { createApp } = require('../app')

const TEST_SCORE_TOKEN = 'test-score-token-fixed'

function newTestApp() {
  return createApp({ dbPath: ':memory:', scoreToken: TEST_SCORE_TOKEN })
}

async function loginAs(app, username, password) {
  const res = await request(app).post('/login').send({ username, password })
  return res.headers['set-cookie'][0].split(';')[0]
}

async function getScores(app, token = TEST_SCORE_TOKEN) {
  const res = await request(app).get(`/score/${token}`).set('Accept', 'application/json')
  return res.body.scores
}

function forgeToken(app, { sub, role, jti = 'forged-' + Math.random() }) {
  return jwt.sign({ sub, role, jti }, app.locals.jwtSecret, { algorithm: 'HS256' })
}

module.exports = { newTestApp, loginAs, getScores, forgeToken, TEST_SCORE_TOKEN }
