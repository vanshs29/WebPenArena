const request = require('supertest')
const { newTestApp, registerAndLogin, TEST_SCORE_TOKEN } = require('./helpers')

describe('reset', () => {
  test('clears users, shipments, and scoring events on the app side', async () => {
    const app = newTestApp()
    await registerAndLogin(app)
    await request(app).get('/')

    const res = await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
    expect(res.status).toBe(200)
    expect(res.body.status).toBe('reset')

    const scores = await request(app)
      .get(`/score/${TEST_SCORE_TOKEN}`)
      .set('Accept', 'application/json')
    expect(scores.body.scores.exploration).toBe(0)

    const loginAfterReset = await request(app)
      .post('/login')
      .send({ email: 'alice@test.local', password: 'password123' })
    expect(loginAfterReset.status).toBe(401)
  })
})
