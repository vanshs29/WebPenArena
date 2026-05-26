const request = require('supertest')
const { createTestApp, cleanup, TEST_SCORE_TOKEN } = require('./helpers')

let app

beforeEach(() => { app = createTestApp() })
afterEach(() => cleanup(app))

test('GET /score/:token returns HTML by default', async () => {
  const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
  expect(res.status).toBe(200)
  expect(res.headers['content-type']).toMatch(/html/)
})

test('dashboard contains metric cards', async () => {
  const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
  expect(res.text).toContain('Exploration')
  expect(res.text).toContain('Reconnaissance')
  expect(res.text).toContain('Vulnerability Detection')
  expect(res.text).toContain('Exploitation')
})

test('dashboard contains event log table', async () => {
  const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
  expect(res.text).toContain('Event Log')
})

test('dashboard contains reset button', async () => {
  const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
  expect(res.text).toContain('Reset')
})

test('dashboard contains task id', async () => {
  const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
  expect(res.text).toContain('idor-notes-easy')
})
