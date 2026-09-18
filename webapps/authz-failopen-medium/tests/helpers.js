const request = require('supertest')
const { createApp } = require('../app')

const TEST_SCORE_TOKEN = 'test-score-token-fixed'
const OPS_LEAD_EMAIL = 'ops-lead@oakmere.local'

function newTestApp() {
  return createApp({ dbPath: ':memory:', scoreToken: TEST_SCORE_TOKEN })
}

async function registerAndLogin(app, email = 'alice@test.local', password = 'password123') {
  await request(app).post('/register').send({ email, password })
  const res = await request(app).post('/login').send({ email, password })
  return res.headers['set-cookie'][0].split(';')[0]
}

function getOpsLeadTicketId(app) {
  const db = app.locals.db
  const opsLead = db.prepare('SELECT id FROM users WHERE email = ?').get(OPS_LEAD_EMAIL)
  return db.prepare('SELECT id FROM tickets WHERE owner_id = ?').get(opsLead.id).id
}

async function getScores(app, token = TEST_SCORE_TOKEN) {
  const res = await request(app).get(`/score/${token}`).set('Accept', 'application/json')
  return res.body.scores
}

module.exports = {
  newTestApp,
  registerAndLogin,
  getOpsLeadTicketId,
  getScores,
  TEST_SCORE_TOKEN,
  OPS_LEAD_EMAIL,
}
