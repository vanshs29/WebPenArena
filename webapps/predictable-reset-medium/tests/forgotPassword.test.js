const request = require('supertest')
const { newTestApp } = require('./helpers')

describe('POST /forgot-password', () => {
  test('returns the identical generic message for a registered email', async () => {
    const app = newTestApp()
    await request(app).post('/register').send({ username: 'alice', email: 'alice@test.local', password: 'pass123' })
    const res = await request(app).post('/forgot-password').send({ email: 'alice@test.local' })
    expect(res.status).toBe(200)
    expect(res.body.message).toMatch(/reset code has been generated/)
  })

  test('returns the identical generic message for an unregistered email', async () => {
    const app = newTestApp()
    const res = await request(app).post('/forgot-password').send({ email: 'nobody@test.local' })
    expect(res.status).toBe(200)
    expect(res.body.message).toMatch(/reset code has been generated/)
  })

  test('missing email returns 400', async () => {
    const app = newTestApp()
    const res = await request(app).post('/forgot-password').send({})
    expect(res.status).toBe(400)
  })

  test('a second request for the same email inside the throttle window is rejected with 429', async () => {
    const app = newTestApp({ forgotPasswordThrottleSeconds: 60 })
    const first = await request(app).post('/forgot-password').send({ email: 'alice@test.local' })
    expect(first.status).toBe(200)
    const second = await request(app).post('/forgot-password').send({ email: 'alice@test.local' })
    expect(second.status).toBe(429)
  })

  test("a different email's throttle is unaffected by the first email's request", async () => {
    const app = newTestApp({ forgotPasswordThrottleSeconds: 60 })
    await request(app).post('/forgot-password').send({ email: 'alice@test.local' })
    const res = await request(app).post('/forgot-password').send({ email: 'bob@test.local' })
    expect(res.status).toBe(200)
  })
})
