const crypto = require('crypto')
const path = require('path')
const request = require('supertest')
const selfsigned = require('selfsigned')
const { createApp } = require('../app')

const TEST_SCORE_TOKEN = 'test-score-token-fixed'
const FIXTURE_KEYS_DIR = path.join(__dirname, 'fixtures', 'keys')
const FIXTURE_EMPTY_SECRET_PATH = path.join(__dirname, 'fixtures', 'empty-secret')
const TRAVERSAL_KID = path.relative(FIXTURE_KEYS_DIR, FIXTURE_EMPTY_SECRET_PATH)

function newTestApp() {
  return createApp({ dbPath: ':memory:', scoreToken: TEST_SCORE_TOKEN, keysDir: FIXTURE_KEYS_DIR })
}

async function registerAndLogin(app, email = 'alice@test.local', password = 'password123', username = 'alice') {
  await request(app).post('/register').send({ username, email, password })
  const res = await request(app).post('/login').send({ email, password })
  return res.headers['set-cookie'][0].split(';')[0]
}

function sessionCookieToBearer(cookie) {
  return cookie.split('=')[1]
}

async function getScores(app, token = TEST_SCORE_TOKEN) {
  const res = await request(app).get(`/score/${token}`).set('Accept', 'application/json')
  return res.body.scores
}

async function generateSelfSignedCert(commonName = 'test-partner.example') {
  const pems = await selfsigned.generate([{ name: 'commonName', value: commonName }], {
    days: 365,
    keySize: 2048,
  })
  const certDer = new crypto.X509Certificate(pems.cert).raw
  const privateKey = crypto.createPrivateKey(pems.private)
  return { certDer, privateKey }
}

function signX5cToken(claims, { certDer, privateKey }) {
  const header = { alg: 'RS256', typ: 'JWT', x5c: [certDer.toString('base64')] }
  const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url')
  const payloadB64 = Buffer.from(JSON.stringify(claims)).toString('base64url')
  const signingInput = `${headerB64}.${payloadB64}`
  const signature = crypto.sign('RSA-SHA256', Buffer.from(signingInput), privateKey)
  return `${signingInput}.${signature.toString('base64url')}`
}

function signKidToken(claims, kid, secret) {
  const header = { alg: 'HS256', typ: 'JWT', kid }
  const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url')
  const payloadB64 = Buffer.from(JSON.stringify(claims)).toString('base64url')
  const signingInput = `${headerB64}.${payloadB64}`
  const sig = crypto.createHmac('sha256', secret).update(signingInput).digest('base64url')
  return `${signingInput}.${sig}`
}

function signArbitraryToken(claims) {
  const header = { alg: 'HS256', typ: 'JWT' }
  const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url')
  const payloadB64 = Buffer.from(JSON.stringify(claims)).toString('base64url')
  const signingInput = `${headerB64}.${payloadB64}`
  const sig = crypto
    .createHmac('sha256', 'some-arbitrary-unrelated-secret')
    .update(signingInput)
    .digest('base64url')
  return `${signingInput}.${sig}`
}

module.exports = {
  newTestApp,
  registerAndLogin,
  sessionCookieToBearer,
  getScores,
  generateSelfSignedCert,
  signX5cToken,
  signKidToken,
  signArbitraryToken,
  TEST_SCORE_TOKEN,
  TRAVERSAL_KID,
}
