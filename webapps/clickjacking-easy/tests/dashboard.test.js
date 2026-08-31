const request = require('supertest')
const { createTestApp, cleanup, TEST_SCORE_TOKEN } = require('./helpers/testApp')

let app

beforeEach(() => { app = createTestApp() })
afterEach(() => cleanup(app))

test('dashboard renders one checkpoint row per exploration surface', async () => {
  const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
  expect(res.status).toBe(200)
  expect(res.text).toContain('GET /')
  expect(res.text).toContain('/account/deactivate')
  expect(res.text).toContain('/pages')
  expect(res.text).toContain('/report')
  expect(res.text).toContain('/about')
})

test('dashboard renders named single-check rows for the other three categories', async () => {
  const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
  expect(res.text).toContain('Reconnaissance')
  expect(res.text).toContain('Vulnerability Detection')
  expect(res.text).toContain('Exploitation')
})

test('dashboard includes a reset button with a confirm dialog', async () => {
  const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
  expect(res.text).toContain(`/score/${TEST_SCORE_TOKEN}/reset`)
  expect(res.text).toContain('confirm(')
})

test('dashboard links to the JSON API', async () => {
  const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
  expect(res.text).toContain('?format=json')
})

test('dashboard shows per-checkpoint weights and the overall point ceiling', async () => {
  const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
  expect(res.text).toContain('0.0 / 5.5')
  expect(res.text).toContain('/ 10.5 pts')
})
