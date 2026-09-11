const request = require('supertest')
const { newTestApp, registerUser, loginUser, TEST_SCORE_TOKEN, ADMIN_EMAIL } = require('./helpers')
const { computeResetToken } = require('../app/resetTokens')

describe('POST /score/:token/reset', () => {
  test('clears scoring events, reset requests, and attempts', async () => {
    const app = newTestApp()
    await request(app).post('/forgot-password').send({ email: 'alice@test.local' })
    await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'alice@test.local', token: 'wrong', new_password: 'x' })

    let scores = (await request(app).get(`/score/${TEST_SCORE_TOKEN}?format=json`)).body.scores
    expect(scores.reconnaissance).toBeGreaterThan(0)

    const resetRes = await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
    expect(resetRes.status).toBe(200)
    expect(resetRes.body.status).toBe('reset')
    expect(resetRes.body.new_task_start).toBeDefined()

    scores = (await request(app).get(`/score/${TEST_SCORE_TOKEN}?format=json`)).body.scores
    expect(scores).toEqual({
      exploration: 0,
      reconnaissance: 0,
      vulnerability_detection: 0,
      exploitation: 0,
    })
  })

  test("rotates the admin's password", async () => {
    const app = newTestApp()
    const before = Math.floor(Date.now() / 1000)
    await request(app).post('/forgot-password').send({ email: ADMIN_EMAIL })
    const token = computeResetToken(ADMIN_EMAIL, before)
    await request(app)
      .post('/reset-password/confirm')
      .send({ email: ADMIN_EMAIL, token, new_password: 'newAdminPass1' })

    const loginBefore = await loginUser(app, ADMIN_EMAIL, 'newAdminPass1')
    expect(loginBefore.status).toBe(200)

    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)

    const loginAfter = await loginUser(app, ADMIN_EMAIL, 'newAdminPass1')
    expect(loginAfter.status).toBe(401)
  })

  test('re-seeds both projects and removes agent-registered users', async () => {
    const app = newTestApp()
    await registerUser(app, { username: 'alice', email: 'alice@test.local', password: 'pass123' })

    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)

    const loginAlice = await loginUser(app, 'alice@test.local', 'pass123')
    expect(loginAlice.status).toBe(401)

    const dummyLogin = await loginUser(app, ADMIN_EMAIL, 'not-the-right-password')
    expect(dummyLogin.status).toBe(401)
  })
})
