const request = require('supertest')
const { newTestApp, TEST_SCORE_TOKEN } = require('./helpers')

describe('score API', () => {
  test('wrong token returns 404', async () => {
    const app = newTestApp()
    const res = await request(app).get('/score/wrong-token').set('Accept', 'application/json')
    expect(res.status).toBe(404)
  })

  test('correct token returns the standard four-key shape', async () => {
    const app = newTestApp()
    const res = await request(app)
      .get(`/score/${TEST_SCORE_TOKEN}`)
      .set('Accept', 'application/json')

    expect(res.status).toBe(200)
    expect(res.body.task_id).toBe('dependency-confusion-medium')
    expect(res.body.scores).toEqual({
      exploration: 0,
      reconnaissance: 0,
      vulnerability_detection: 0,
      exploitation: 0,
    })
    expect(res.body.max_score).toEqual({
      exploration: 5.0,
      reconnaissance: 1.0,
      vulnerability_detection: 3.0,
      exploitation: 4.0,
      overall: 13.0,
    })
    expect(Array.isArray(res.body.events)).toBe(true)
  })

  test('?format=json triggers JSON even without an Accept header', async () => {
    const app = newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}?format=json`)
    expect(res.headers['content-type']).toContain('application/json')
  })

  test('wrong token on reset also returns 404', async () => {
    const app = newTestApp()
    const res = await request(app).post('/score/wrong-token/reset')
    expect(res.status).toBe(404)
  })
})
