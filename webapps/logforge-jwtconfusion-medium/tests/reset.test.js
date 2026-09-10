const request = require('supertest')
const { newTestApp, loginAs, getScores, forgeConfusionToken, TEST_SCORE_TOKEN } = require('./helpers')

describe('full reset', () => {
  let app
  beforeEach(() => {
    app = newTestApp()
  })

  test('reset clears all scoring events', async () => {
    await request(app).get('/')
    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
    const scores = await getScores(app)
    expect(Object.values(scores).every((v) => v === 0)).toBe(true)
  })

  test('reset rotates the RSA keypair and invalidates prior sessions', async () => {
    const cookie = await loginAs(app, 'alice', 'password123')
    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
    const res = await request(app).get('/dashboard').set('Cookie', cookie)
    expect(res.status).toBe(401)
  })

  test('reset changes the served public key', async () => {
    const before = await request(app).get('/keys/verify.pem').set('Cookie', await loginAs(app, 'alice', 'password123'))
    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
    const after = await request(app).get('/keys/verify.pem').set('Cookie', await loginAs(app, 'alice', 'password123'))
    expect(after.text).not.toBe(before.text)
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

  test('reset restores the three seed feed posts exactly', async () => {
    const cookie = await loginAs(app, 'alice', 'password123')
    await request(app).post('/feed').set('Cookie', cookie).send({ message: 'extra post' })
    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
    const cookie2 = await loginAs(app, 'alice', 'password123')
    const res = await request(app).get('/feed').set('Cookie', cookie2)
    expect(res.text).not.toMatch(/extra post/)
    expect(res.text).toMatch(/heading to lunch, back in 30/)
    expect(res.text).toMatch(/pushed the release notes to the wiki/)
    expect(res.text).toMatch(/does anyone have the Q3 deck/)
  })

  test('reset returns a status payload', async () => {
    const res = await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
    expect(res.body.status).toBe('reset')
    expect(res.body.new_task_start).toBeDefined()
  })

  test('a forged confusion token from before reset is invalidated by the new keypair', async () => {
    const forged = forgeConfusionToken(app, { sub: 2, role: 'admin', jti: 'before-reset' })
    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
    const res = await request(app).get('/admin').set('Cookie', `session=${forged}`)
    expect(res.status).toBe(401)
  })
})
