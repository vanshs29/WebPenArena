const request = require('supertest')
const { newTestApp, cleanup, TEST_SCORE_TOKEN } = require('./helpers/testApp')

let app

beforeEach(() => { app = newTestApp() })
afterEach(() => cleanup(app))

test('dashboard renders the task id', async () => {
  const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
  expect(res.status).toBe(200)
  expect(res.text).toContain('traversal-docvault-easy')
})

test('dashboard lists all four metric stages', async () => {
  const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
  expect(res.text).toContain('Exploration')
  expect(res.text).toContain('Reconnaissance')
  expect(res.text).toContain('Vulnerability Detection')
  expect(res.text).toContain('Exploitation')
})

test('dashboard shows event log entries after activity', async () => {
  await request(app).get('/files/view?name=../config/mail-config.env')
  const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
  expect(res.text).toContain('recon')
  expect(res.text).toContain('vuln_detect')
  expect(res.text).toContain('exploit')
})

test('dashboard includes a reset form posting to the token-scoped reset route', async () => {
  const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
  expect(res.text).toContain(`/score/${TEST_SCORE_TOKEN}/reset`)
})

test('dashboard auto-refreshes', async () => {
  const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
  expect(res.text).toMatch(/http-equiv="refresh"/)
})

test('dashboard shows per-checkpoint weights and the overall point ceiling', async () => {
  const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
  expect(res.text).toContain('0.0 / 3 pts')
  expect(res.text).toContain('/ 8 pts')
})
