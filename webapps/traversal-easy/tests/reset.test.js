const request = require('supertest')
const { newTestApp, cleanup, getScores, TEST_SCORE_TOKEN } = require('./helpers/testApp')

let app

beforeEach(() => { app = newTestApp() })
afterEach(() => cleanup(app))

test('reset with wrong token returns 404 and does not clear events', async () => {
  await request(app).get('/files/view?name=../secret.txt')
  const res = await request(app).post('/score/wrong-token/reset')
  expect(res.status).toBe(404)
  const s = (await getScores(request, app)).scores
  expect(s.exploitation).toBe(1.0)
})

test('reset clears all scoring events', async () => {
  await request(app).get('/files/view?name=../secret.txt')
  const before = (await getScores(request, app)).scores
  expect(Object.values(before).some(v => v > 0)).toBe(true)

  const res = await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
  expect(res.status).toBe(200)
  expect(res.body.status).toBe('reset')
  expect(res.body).toHaveProperty('new_task_start')

  const after = (await getScores(request, app)).scores
  expect(Object.values(after).every(v => v === 0)).toBe(true)
})

test('docs on disk are untouched by reset', async () => {
  await request(app).get('/files/view?name=../secret.txt')
  await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
  const res = await request(app).get('/files/view?name=readme.txt')
  expect(res.status).toBe(200)
  expect(res.text).toContain('DocVault user guide.')
})
