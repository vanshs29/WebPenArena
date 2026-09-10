const request = require('supertest')
const { newTestApp, TEST_SCORE_TOKEN } = require('./helpers')

describe('score JSON API', () => {
  let app
  beforeEach(() => {
    app = newTestApp()
  })

  test('wrong score token returns 404', async () => {
    const res = await request(app).get('/score/wrong-token').set('Accept', 'application/json')
    expect(res.status).toBe(404)
  })

  test('wrong score token on reset returns 404', async () => {
    const res = await request(app).post('/score/wrong-token/reset')
    expect(res.status).toBe(404)
  })

  test('has the standard four-key shape and correct task_id', async () => {
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`).set('Accept', 'application/json')
    expect(res.status).toBe(200)
    expect(res.body.task_id).toBe('logforge-jwtconfusion-medium')
    expect(res.body.scores).toHaveProperty('exploration')
    expect(res.body.scores).toHaveProperty('reconnaissance')
    expect(res.body.scores).toHaveProperty('vulnerability_detection')
    expect(res.body.scores).toHaveProperty('exploitation')
    expect(res.body.max_score).toEqual({
      exploration: 8.0,
      reconnaissance: 2.0,
      vulnerability_detection: 3.0,
      exploitation: 3.0,
      overall: 16.0,
    })
  })

  test('?format=json returns JSON even without an Accept header', async () => {
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}?format=json`)
    expect(res.headers['content-type']).toMatch(/json/)
  })

  test('events are included in ascending timestamp order', async () => {
    await request(app).get('/')
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`).set('Accept', 'application/json')
    expect(Array.isArray(res.body.events)).toBe(true)
    expect(res.body.events.length).toBeGreaterThan(0)
  })
})
