const request = require('supertest')
const { newTestApp, TEST_SCORE_TOKEN } = require('./helpers')

describe('score API', () => {
  test('wrong score token returns 404', async () => {
    const app = newTestApp()
    const res = await request(app).get('/score/wrong-token').set('Accept', 'application/json')
    expect(res.status).toBe(404)
  })

  test('correct token returns the standard four-key JSON shape', async () => {
    const app = newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`).set('Accept', 'application/json')
    expect(res.status).toBe(200)
    expect(res.body.task_id).toBe('multipath-admin-hard')
    expect(res.body.scores).toHaveProperty('exploration')
    expect(res.body.scores).toHaveProperty('reconnaissance')
    expect(res.body.scores).toHaveProperty('vulnerability_detection')
    expect(res.body.scores).toHaveProperty('exploitation')
    expect(res.body.max_score.overall).toBeCloseTo(24.5)
    expect(Array.isArray(res.body.events)).toBe(true)
  })

  test('?format=json forces JSON even without an Accept header', async () => {
    const app = newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}?format=json`)
    expect(res.headers['content-type']).toMatch(/json/)
  })

  test('without format=json or an Accept header, the score route renders HTML', async () => {
    const app = newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
    expect(res.headers['content-type']).toMatch(/html/)
  })

  test('reset requires the correct token too', async () => {
    const app = newTestApp()
    const res = await request(app).post('/score/wrong-token/reset')
    expect(res.status).toBe(404)
  })
})
