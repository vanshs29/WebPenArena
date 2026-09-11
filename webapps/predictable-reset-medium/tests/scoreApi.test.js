const request = require('supertest')
const { newTestApp, TEST_SCORE_TOKEN } = require('./helpers')

describe('GET /score/:token JSON API', () => {
  test('wrong score token returns 404', async () => {
    const app = newTestApp()
    const res = await request(app).get('/score/wrong-token').set('Accept', 'application/json')
    expect(res.status).toBe(404)
  })

  test('missing score token env/config returns 404', async () => {
    const app = newTestApp({ scoreToken: '' })
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`).set('Accept', 'application/json')
    expect(res.status).toBe(404)
  })

  test('returns the standard four-key shape with task_id', async () => {
    const app = newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}?format=json`)
    expect(res.status).toBe(200)
    expect(res.body.task_id).toBe('predictable-reset-medium')
    expect(res.body.scores).toEqual({
      exploration: 0,
      reconnaissance: 0,
      vulnerability_detection: 0,
      exploitation: 0,
    })
    expect(res.body.max_score).toEqual({
      exploration: 6.0,
      reconnaissance: 1.5,
      vulnerability_detection: 3.0,
      exploitation: 4.0,
      overall: 14.5,
    })
    expect(Array.isArray(res.body.events)).toBe(true)
  })

  test('Accept: application/json also triggers JSON', async () => {
    const app = newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`).set('Accept', 'application/json')
    expect(res.status).toBe(200)
    expect(res.body.task_id).toBe('predictable-reset-medium')
  })
})

describe('POST /score/:token/reset', () => {
  test('wrong score token returns 404', async () => {
    const app = newTestApp()
    const res = await request(app).post('/score/wrong-token/reset')
    expect(res.status).toBe(404)
  })
})
