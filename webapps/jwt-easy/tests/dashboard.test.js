const request = require('supertest')
const { newTestApp, makeAlgNoneToken, TEST_SCORE_TOKEN } = require('./helpers/testApp')

test('dashboard renders the task id', async () => {
  const app = newTestApp()
  const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
  expect(res.status).toBe(200)
  expect(res.text).toContain('jwt-devblog-easy')
})

test('dashboard lists all four metric stages', async () => {
  const app = newTestApp()
  const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
  expect(res.text).toContain('Exploration')
  expect(res.text).toContain('Reconnaissance')
  expect(res.text).toContain('Vulnerability Detection')
  expect(res.text).toContain('Exploitation')
})

test('dashboard shows event log entries after activity', async () => {
  const app = newTestApp()
  const token = makeAlgNoneToken({ sub: '0', role: 'admin' })
  await request(app).get('/admin').set('Authorization', `Bearer ${token}`)
  const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
  expect(res.text).toContain('recon')
  expect(res.text).toContain('vuln_detect')
  expect(res.text).toContain('exploit')
})

test('dashboard includes a reset form posting to the token-scoped reset route', async () => {
  const app = newTestApp()
  const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
  expect(res.text).toContain(`/score/${TEST_SCORE_TOKEN}/reset`)
})

test('dashboard auto-refreshes', async () => {
  const app = newTestApp()
  const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
  expect(res.text).toMatch(/http-equiv="refresh"/)
})
