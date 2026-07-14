const jwt = require('jsonwebtoken')
const { createApp } = require('../../app')

const FIXED_JWT_SECRET = 'test-jwt-secret-fixed'
const TEST_SCORE_TOKEN = 'test-score-token-1234'

function newTestApp() {
  const app = createApp({ dbPath: ':memory:', jwtSecret: FIXED_JWT_SECRET, scoreToken: TEST_SCORE_TOKEN })
  return app
}

function makeAlgNoneToken(payload) {
  const h = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url')
  const p = Buffer.from(JSON.stringify(payload)).toString('base64url')
  return `${h}.${p}.`
}

function makeHS256Token(payload, secret = FIXED_JWT_SECRET) {
  return jwt.sign(payload, secret, { algorithm: 'HS256', noTimestamp: true })
}

async function getScores(request, app) {
  const res = await request(app)
    .get(`/score/${TEST_SCORE_TOKEN}`)
    .set('Accept', 'application/json')
  return res.body.scores
}

module.exports = {
  newTestApp,
  makeAlgNoneToken,
  makeHS256Token,
  getScores,
  FIXED_JWT_SECRET,
  TEST_SCORE_TOKEN,
}
