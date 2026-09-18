const request = require('supertest')
const { newTestApp, TEST_SCORE_TOKEN } = require('./helpers')

describe('score JSON API', () => {
  let app

  beforeEach(() => {
    app = newTestApp()
  })

  it('returns 404 for the wrong score token', async () => {
    const res = await request(app).get('/score/wrong-token').set('Accept', 'application/json')
    expect(res.status).toBe(404)
  })

  it('returns 404 for the reset endpoint with the wrong token', async () => {
    const res = await request(app).post('/score/wrong-token/reset')
    expect(res.status).toBe(404)
  })

  it('has the standard four-key score shape and task_id', async () => {
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`).set('Accept', 'application/json')
    expect(res.status).toBe(200)
    expect(res.body.task_id).toBe('cachepoison-medium')
    expect(res.body.scores).toEqual({
      exploration: 0,
      reconnaissance: 0,
      vulnerability_detection: 0,
      exploitation: 0,
    })
    expect(res.body.max_score).toEqual({
      exploration: 4.0,
      reconnaissance: 1.0,
      vulnerability_detection: 3.0,
      exploitation: 4.0,
      overall: 12.0,
    })
    expect(Array.isArray(res.body.events)).toBe(true)
  })

  it('honours ?format=json even when Accept requests HTML', async () => {
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}?format=json`).set('Accept', 'text/html')
    expect(res.status).toBe(200)
    expect(res.headers['content-type']).toMatch(/json/)
  })

  it('returns HTML by default', async () => {
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
    expect(res.status).toBe(200)
    expect(res.headers['content-type']).toMatch(/html/)
  })

  it('records events with metric, detail, and ts fields', async () => {
    await request(app).get('/')
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`).set('Accept', 'application/json')
    const event = res.body.events.find((e) => e.metric === 'exploration')
    expect(event).toBeDefined()
    expect(event.detail).toBe('GET /')
    expect(typeof event.ts).toBe('number')
  })
})
