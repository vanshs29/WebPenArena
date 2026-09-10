const request = require('supertest')
const { newTestApp, registerAndLogin, getScores, TEST_SCORE_TOKEN, wait } = require('./helpers')

describe('full reset', () => {
  test('wrong token on reset returns 404', async () => {
    const app = newTestApp()
    const res = await request(app).post('/score/wrong-token/reset')
    expect(res.status).toBe(404)
  })

  test('reset returns the standard reset shape', async () => {
    const app = newTestApp()
    const res = await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
    expect(res.status).toBe(200)
    expect(res.body.status).toBe('reset')
    expect(typeof res.body.new_task_start).toBe('number')
  })

  test('reset clears scoring events and score returns to zero', async () => {
    const app = newTestApp(30)
    const cookie = await registerAndLogin(app)
    await request(app).post('/wallet/redeem').set('Cookie', cookie)
      .send({ code: 'WELCOME50', idempotency_key: 'k1' })
    await wait(60)
    expect((await getScores(app)).reconnaissance).toBeGreaterThan(0)

    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
    const scores = await getScores(app)
    expect(scores).toEqual({
      exploration: 0,
      reconnaissance: 0,
      vulnerability_detection: 0,
      exploitation: 0,
    })
  })

  test('reset restores WELCOME50 to unused', async () => {
    const app = newTestApp(30)
    const cookie = await registerAndLogin(app)
    await request(app).post('/wallet/redeem').set('Cookie', cookie)
      .send({ code: 'WELCOME50', idempotency_key: 'k1' })
    await wait(60)

    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)

    const newCookie = await registerAndLogin(app, 'bob', 'password456')
    const res = await request(app).post('/wallet/redeem').set('Cookie', newCookie)
      .send({ code: 'WELCOME50', idempotency_key: 'new-key' })
    expect(res.status).toBe(202)
  })

  test('reset removes agent-registered users and purchases', async () => {
    const app = newTestApp(30)
    await registerAndLogin(app)
    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)

    const login = await request(app).post('/login').send({ username: 'alice', password: 'password123' })
    expect(login.status).toBe(401)
  })
})
