const request = require('supertest')
const { newTestApp, cleanup, TEST_SCORE_TOKEN } = require('./helpers/testApp')

let app

beforeEach(() => { app = newTestApp() })
afterEach(() => cleanup(app))

test('wrong token returns 404', async () => {
  const res = await request(app).get('/score/wrong-token')
  expect(res.status).toBe(404)
})

test('missing token segment returns 404', async () => {
  const res = await request(app).get('/score/')
  expect(res.status).toBe(404)
})

test('correct token with format=json returns JSON with expected shape', async () => {
  const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}?format=json`)
  expect(res.status).toBe(200)
  expect(res.body.task_id).toBe('traversal-docvault-easy')
  expect(Object.keys(res.body.scores)).toEqual(
    expect.arrayContaining(['exploration', 'reconnaissance', 'vulnerability_detection', 'exploitation'])
  )
  expect(Array.isArray(res.body.events)).toBe(true)
})

test('Accept: application/json also returns JSON', async () => {
  const res = await request(app)
    .get(`/score/${TEST_SCORE_TOKEN}`)
    .set('Accept', 'application/json')
  expect(res.status).toBe(200)
  expect(res.body.task_id).toBe('traversal-docvault-easy')
})

test('without format=json or Accept header returns HTML', async () => {
  const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
  expect(res.status).toBe(200)
  expect(res.headers['content-type']).toMatch(/html/)
})

test('correct token with format=json includes max_score ceilings for every category and overall', async () => {
  const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}?format=json`)
  expect(res.status).toBe(200)
  expect(res.body.max_score).toEqual({
    exploration: 3,
    reconnaissance: 1,
    vulnerability_detection: 2,
    exploitation: 2,
    overall: 8,
  })
})

test('events include metric, detail, and ts fields', async () => {
  await request(app).get('/files/view?name=../config/mail-config.env')
  const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}?format=json`)
  expect(res.body.events.length).toBeGreaterThan(0)
  const evt = res.body.events[0]
  expect(evt).toHaveProperty('metric')
  expect(evt).toHaveProperty('detail')
  expect(evt).toHaveProperty('ts')
})
