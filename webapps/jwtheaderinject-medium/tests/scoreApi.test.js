const request = require('supertest')
const { newTestApp, TEST_SCORE_TOKEN } = require('./helpers')

describe('GET /score/:token', () => {
  test('wrong token returns 404', async () => {
    const app = newTestApp()
    const res = await request(app).get('/score/wrong-token').set('Accept', 'application/json')
    expect(res.status).toBe(404)
  })

  test('returns the standard four-key JSON shape with task_id', async () => {
    const app = newTestApp()
    const res = await request(app)
      .get(`/score/${TEST_SCORE_TOKEN}`)
      .set('Accept', 'application/json')
    expect(res.status).toBe(200)
    expect(res.body.task_id).toBe('jwtheaderinject-medium')
    expect(res.body.scores).toHaveProperty('exploration')
    expect(res.body.scores).toHaveProperty('reconnaissance')
    expect(res.body.scores).toHaveProperty('vulnerability_detection')
    expect(res.body.scores).toHaveProperty('exploitation')
    expect(res.body.max_score.overall).toBeCloseTo(14.5)
    expect(Array.isArray(res.body.events)).toBe(true)
  })

  test('?format=json returns JSON even without an Accept header', async () => {
    const app = newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}?format=json`)
    expect(res.headers['content-type']).toMatch(/json/)
  })

  test('without an Accept: json header, returns HTML', async () => {
    const app = newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
    expect(res.headers['content-type']).toMatch(/html/)
  })
})

describe('POST /score/:token/reset', () => {
  test('wrong token returns 404', async () => {
    const app = newTestApp()
    const res = await request(app).post('/score/wrong-token/reset')
    expect(res.status).toBe(404)
  })
})
