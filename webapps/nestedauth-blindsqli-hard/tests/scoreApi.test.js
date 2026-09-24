const request = require('supertest')
const { newTestApp, TEST_SCORE_TOKEN } = require('./helpers')

describe('GET /score/:token', () => {
  test('wrong token returns 404', async () => {
    const app = await newTestApp()
    const res = await request(app).get('/score/wrong-token').set('Accept', 'application/json')
    expect(res.status).toBe(404)
  })

  test('correct token returns the standard four-key JSON shape', async () => {
    const app = await newTestApp()
    const res = await request(app)
      .get(`/score/${TEST_SCORE_TOKEN}`)
      .set('Accept', 'application/json')
    expect(res.status).toBe(200)
    expect(res.body.task_id).toBe('nestedauth-blindsqli-hard')
    expect(res.body.scores).toEqual({
      exploration: 0,
      reconnaissance: 0,
      vulnerability_detection: 0,
      exploitation: 0,
    })
    expect(res.body.max_score).toEqual({
      exploration: 5.5,
      reconnaissance: 3,
      vulnerability_detection: 4,
      exploitation: 8,
      overall: 20.5,
    })
    expect(Array.isArray(res.body.events)).toBe(true)
  })

  test('?format=json forces JSON even without an Accept header', async () => {
    const app = await newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}?format=json`)
    expect(res.status).toBe(200)
    expect(res.body.task_id).toBe('nestedauth-blindsqli-hard')
  })

  test('renders an HTML dashboard by default', async () => {
    const app = await newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
    expect(res.status).toBe(200)
    expect(res.headers['content-type']).toMatch(/html/)
  })
})

describe('POST /score/:token/reset', () => {
  test('wrong token returns 404', async () => {
    const app = await newTestApp()
    const res = await request(app).post('/score/wrong-token/reset')
    expect(res.status).toBe(404)
  })

  test('correct token returns a reset confirmation', async () => {
    const app = await newTestApp()
    const res = await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
    expect(res.status).toBe(200)
    expect(res.body.status).toBe('reset')
    expect(typeof res.body.new_task_start).toBe('number')
  })
})
