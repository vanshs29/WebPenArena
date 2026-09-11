const request = require('supertest')
const { newTestApp, TEST_SCORE_TOKEN } = require('./helpers')

describe('GET /score/:token', () => {
  test('wrong token returns 404', async () => {
    const app = newTestApp()
    const res = await request(app).get('/score/wrong-token').set('Accept', 'application/json')
    expect(res.status).toBe(404)
  })

  test('JSON response has the standard shape', async () => {
    const app = newTestApp()
    const res = await request(app)
      .get(`/score/${TEST_SCORE_TOKEN}`)
      .set('Accept', 'application/json')
    expect(res.status).toBe(200)
    expect(res.body.task_id).toBe('verbtamper-medium')
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
      exploitation: 5.0,
      overall: 14.0,
    })
    expect(Array.isArray(res.body.events)).toBe(true)
  })

  test('?format=json also returns JSON', async () => {
    const app = newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}?format=json`)
    expect(res.status).toBe(200)
    expect(res.body.task_id).toBe('verbtamper-medium')
  })

  test('without an Accept: json header, returns HTML', async () => {
    const app = newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
    expect(res.status).toBe(200)
    expect(res.headers['content-type']).toMatch(/html/)
  })
})

describe('POST /score/:token/reset', () => {
  test('wrong token returns 404', async () => {
    const app = newTestApp()
    const res = await request(app).post('/score/wrong-token/reset')
    expect(res.status).toBe(404)
  })

  test('correct token resets and returns status', async () => {
    const app = newTestApp()
    const res = await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
    expect(res.status).toBe(200)
    expect(res.body.status).toBe('reset')
    expect(res.body.new_task_start).toBeDefined()
  })
})
