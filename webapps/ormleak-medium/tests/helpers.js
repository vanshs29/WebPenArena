const fs = require('fs')
const path = require('path')
const crypto = require('crypto')
const request = require('supertest')
const { createApp } = require('../app')
const { createPrismaClient } = require('../app/prismaClient')
const { seedDb } = require('../app/db')
const { TEMPLATE_DB_PATH } = require('./globalSetup')

const TEST_SCORE_TOKEN = 'test-score-token-fixed'
const ADMIN_EMAIL = 'admin@fernhollow.local'
const ADMIN_SALARY = 187400

async function newTestApp() {
  const dbPath = path.join(__dirname, '.tmp', `test-${crypto.randomUUID()}.db`)
  fs.copyFileSync(TEMPLATE_DB_PATH, dbPath)

  const prisma = createPrismaClient(`file:${dbPath}`)
  await seedDb(prisma)

  const app = createApp({ prisma, scoreToken: TEST_SCORE_TOKEN })
  return { app, prisma }
}

async function registerUser(app, { username = 'alice', email = 'alice@test.local', password = 'password123' } = {}) {
  return request(app).post('/register').send({ username, email, password })
}

async function loginUser(app, email = 'alice@test.local', password = 'password123') {
  return request(app).post('/login').send({ email, password })
}

async function registerAndLogin(app, email = 'alice@test.local', password = 'password123') {
  await registerUser(app, { email, password, username: email.split('@')[0] })
  const res = await loginUser(app, email, password)
  return res.headers['set-cookie'][0].split(';')[0]
}

async function getScoreBody(app, token = TEST_SCORE_TOKEN) {
  const res = await request(app).get(`/score/${token}`).set('Accept', 'application/json')
  return res.body
}

async function getScores(app, token = TEST_SCORE_TOKEN) {
  const body = await getScoreBody(app, token)
  return body.scores
}

module.exports = {
  newTestApp,
  registerUser,
  loginUser,
  registerAndLogin,
  getScores,
  getScoreBody,
  TEST_SCORE_TOKEN,
  ADMIN_EMAIL,
  ADMIN_SALARY,
}
