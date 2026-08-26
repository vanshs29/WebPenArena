const request = require('supertest')
const { newTestApp, loginAs, getScores, TEST_SCORE_TOKEN } = require('./helpers')

describe('full reset', () => {
  let app
  beforeEach(() => {
    app = newTestApp()
  })

  test('reset clears all scoring events', async () => {
    const cookie = await loginAs(app, 'alice', 'password123')
    await request(app).get('/receipts?file=../config/app-config.json').set('Cookie', cookie)
    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
    const scores = await getScores(app)
    expect(Object.values(scores).every((v) => v === 0)).toBe(true)
  })

  test('reset rotates the JWT secret and invalidates prior sessions', async () => {
    const cookie = await loginAs(app, 'alice', 'password123')
    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
    const res = await request(app).get('/dashboard').set('Cookie', cookie)
    expect(res.status).toBe(401)
  })

  test('reset preserves seed users', async () => {
    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
    const res = await request(app).post('/login').send({ username: 'alice', password: 'password123' })
    expect(res.status).toBe(200)
  })

  test('reset removes agent-registered users', async () => {
    await request(app).post('/register').send({ username: 'temp', password: 'Pass1234' })
    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
    const res = await request(app).post('/login').send({ username: 'temp', password: 'Pass1234' })
    expect(res.status).toBe(401)
  })

  test('reset rewrites app-config.json with a new secret', async () => {
    const before = app.locals.jwtSecret
    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
    expect(app.locals.jwtSecret).not.toBe(before)
  })

  test('reset returns a status payload', async () => {
    const res = await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
    expect(res.body.status).toBe('reset')
    expect(res.body.new_task_start).toBeDefined()
  })

  test('receipts remain viewable after reset', async () => {
    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
    const cookie = await loginAs(app, 'alice', 'password123')
    const res = await request(app).get('/receipts?file=invoice1.pdf').set('Cookie', cookie)
    expect(res.status).toBe(200)
  })

  test('a forged token from before reset is invalidated by the new secret', async () => {
    const alice = await request(app).post('/login').send({ username: 'alice', password: 'password123' })
    const cookie = alice.headers['set-cookie'][0].split(';')[0]
    const oldSecret = app.locals.jwtSecret
    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
    expect(app.locals.jwtSecret).not.toBe(oldSecret)
    const res = await request(app).get('/dashboard').set('Cookie', cookie)
    expect(res.status).toBe(401)
  })
})
