const request = require('supertest')
const { createTestApp, cleanup, registerAndLogin, loginAs, getScores, TEST_SCORE_TOKEN } = require('./helpers/testApp')
const { VICTIM_EMAIL, VICTIM_PASSWORD } = require('../src/db')

let app

beforeEach(() => { app = createTestApp() })
afterEach(() => cleanup(app))

test('reset clears recorded scoring events', async () => {
  const token = await registerAndLogin(app, 'reset1@example.com', 'pw12345')
  await request(app).get('/').set('Authorization', `Bearer ${token}`)

  await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)

  const scores = await getScores(app)
  expect(scores.exploration).toBe(0)
})

test('reset clears stored pages and reports', async () => {
  const token = await registerAndLogin(app, 'reset2@example.com', 'pw12345')
  const page = await request(app)
    .post('/pages')
    .set('Authorization', `Bearer ${token}`)
    .set('Content-Type', 'application/json')
    .send({ html: '<p>x</p>' })

  await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)

  const res = await request(app).get(`/pages/${page.body.id}`)
  expect(res.status).toBe(404)
})

test('reset restores the victim subscription to active', async () => {
  const victimToken = await loginAs(app, VICTIM_EMAIL, VICTIM_PASSWORD)
  await request(app)
    .post('/account/deactivate')
    .set('Authorization', `Bearer ${victimToken}`)
    .set('Sec-Fetch-Dest', 'iframe')

  await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)

  const freshToken = await loginAs(app, VICTIM_EMAIL, VICTIM_PASSWORD)
  const res = await request(app)
    .get('/account/deactivate')
    .set('Authorization', `Bearer ${freshToken}`)
  expect(res.text).toContain('Status: Active')
})
