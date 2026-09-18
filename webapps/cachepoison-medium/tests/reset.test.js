const request = require('supertest')
const { newTestApp, TEST_SCORE_TOKEN } = require('./helpers')

describe('full reset', () => {
  let app

  beforeEach(() => {
    app = newTestApp()
  })

  it('returns a reset confirmation with a new_task_start timestamp', async () => {
    const res = await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
    expect(res.status).toBe(200)
    expect(res.body.status).toBe('reset')
    expect(typeof res.body.new_task_start).toBe('number')
  })

  it('clears all scoring events', async () => {
    await request(app).get('/')
    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`).set('Accept', 'application/json')
    expect(res.body.scores.exploration).toBe(0)
    expect(res.body.events).toEqual([])
  })

  it('clears the cache store, allowing a fresh MISS after reset', async () => {
    await request(app).get('/articles')
    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
    const res = await request(app).get('/articles')
    expect(res.headers['x-cache']).toBe('MISS')
  })

  it('removes agent-registered users', async () => {
    await request(app)
      .post('/register')
      .send({ username: 'temp', email: 'temp@test.local', password: 'pw' })
    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
    const res = await request(app).post('/login').send({ email: 'temp@test.local', password: 'pw' })
    expect(res.status).toBe(401)
  })

  it('leaves the three seed articles untouched', async () => {
    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
    const res = await request(app).get('/articles/1')
    expect(res.status).toBe(200)
    const res3 = await request(app).get('/articles/3')
    expect(res3.status).toBe(200)
  })
})
