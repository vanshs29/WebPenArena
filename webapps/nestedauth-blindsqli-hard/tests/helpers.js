const request = require('supertest')
const { createApp } = require('../app')

const TEST_SCORE_TOKEN = 'test-score-token-fixed'

async function newTestApp() {
  return createApp({ scoreToken: TEST_SCORE_TOKEN })
}

async function registerAndLogin(
  app,
  { orgName = `Test Org ${Math.random().toString(36).slice(2)}`, name = 'Alice Test', email, password = 'password123' } = {}
) {
  const finalEmail = email || `alice-${Math.random().toString(36).slice(2)}@test.local`
  await request(app).post('/register').send({ orgName, name, email: finalEmail, password })
  const res = await request(app).post('/login').send({ email: finalEmail, password })
  const cookie = res.headers['set-cookie'][0].split(';')[0]
  return { cookie, email: finalEmail, orgName }
}

async function getScores(app, token = TEST_SCORE_TOKEN) {
  const res = await request(app).get(`/score/${token}`).set('Accept', 'application/json')
  return res.body.scores
}

async function getFullScore(app, token = TEST_SCORE_TOKEN) {
  const res = await request(app).get(`/score/${token}`).set('Accept', 'application/json')
  return res.body
}

async function graphqlRequest(app, cookie, query, variables) {
  return request(app)
    .post('/graphql')
    .set('Cookie', cookie)
    .set('Content-Type', 'application/json')
    .set('Accept', 'application/json')
    .send({ query, variables })
}

module.exports = {
  newTestApp,
  registerAndLogin,
  getScores,
  getFullScore,
  graphqlRequest,
  TEST_SCORE_TOKEN,
}
