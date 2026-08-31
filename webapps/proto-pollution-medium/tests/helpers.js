const request = require('supertest')
const { createApp } = require('../app')
const { cleanPollutedPrototype } = require('../app/scoring')

const TEST_SCORE_TOKEN = 'test-score-token-fixed'

function newTestApp() {
  return createApp({ dbPath: ':memory:', scoreToken: TEST_SCORE_TOKEN })
}

async function loginAs(app, email, password) {
  const res = await request(app).post('/login').send({ email, password })
  return res.headers['set-cookie'][0].split(';')[0]
}

async function getScores(app, token = TEST_SCORE_TOKEN) {
  const res = await request(app).get(`/score/${token}`).set('Accept', 'application/json')
  return res.body.scores
}

// supertest/superagent special-case the "__proto__" own-property key on plain
// object bodies (via Object.assign-style merging internally), so `.send({
// __proto__: {...} })` silently serializes to "{}" over the wire and never
// reaches the server. A raw pre-serialized JSON string bypasses that merge
// entirely and is what actually reproduces the real-world attack (a raw HTTP
// body an attacker sends is never a JS object literal to begin with).
function sendRawJson(agent, rawJsonString) {
  return agent.set('Content-Type', 'application/json').send(rawJsonString)
}

// Object.prototype is shared process-wide state. Without this, a pollution
// assertion in one test leaks into every subsequent test in the run.
afterEach(() => {
  cleanPollutedPrototype()
})

module.exports = { newTestApp, loginAs, getScores, sendRawJson, TEST_SCORE_TOKEN }
