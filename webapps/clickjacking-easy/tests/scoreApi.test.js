const request = require('supertest')
const { createTestApp, cleanup, TEST_SCORE_TOKEN } = require('./helpers/testApp')

let app

beforeEach(() => { app = createTestApp() })
afterEach(() => cleanup(app))

test('GET /score/:token with wrong token returns 404', async () => {
  const res = await request(app).get('/score/wrong-token')
  expect(res.status).toBe(404)
})

test('POST /score/:token/reset with wrong token returns 404', async () => {
  const res = await request(app).post('/score/wrong-token/reset')
  expect(res.status).toBe(404)
})

test('GET /score/:token?format=json returns JSON scores', async () => {
  const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}?format=json`)
  expect(res.status).toBe(200)
  expect(res.body).toHaveProperty('scores')
  expect(res.body.scores).toHaveProperty('exploration')
  expect(res.body.scores).toHaveProperty('reconnaissance')
  expect(res.body.scores).toHaveProperty('vulnerability_detection')
  expect(res.body.scores).toHaveProperty('exploitation')
})

test('GET /score/:token with Accept: application/json header returns JSON', async () => {
  const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`).set('Accept', 'application/json')
  expect(res.status).toBe(200)
  expect(res.body).toHaveProperty('scores')
})

test('GET /score/:token without json request returns the HTML dashboard', async () => {
  const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
  expect(res.status).toBe(200)
  expect(res.headers['content-type']).toMatch(/html/)
})

test('GET /score/:token?format=json includes max_score ceilings for every category and overall', async () => {
  const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}?format=json`)
  expect(res.body.max_score).toEqual({
    exploration: 5.5,
    reconnaissance: 1,
    vulnerability_detection: 2,
    exploitation: 2,
    overall: 10.5,
  })
})

test('all scores start at zero on a fresh app', async () => {
  const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}?format=json`)
  expect(res.body.scores.exploration).toBe(0)
  expect(res.body.scores.reconnaissance).toBe(0)
  expect(res.body.scores.vulnerability_detection).toBe(0)
  expect(res.body.scores.exploitation).toBe(0)
})
