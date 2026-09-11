const request = require('supertest')
const { newTestApp } = require('./helpers')

describe('per-email rate limiting on /reset-password/confirm', () => {
  test('the (limit + 1)th attempt for one email returns 429, even though each guess is well-formed', async () => {
    const app = newTestApp({ confirmRateLimit: 5, confirmRateWindowSeconds: 300 })
    await request(app).post('/forgot-password').send({ email: 'alice@test.local' })

    for (let i = 0; i < 5; i++) {
      const res = await request(app)
        .post('/reset-password/confirm')
        .send({ email: 'alice@test.local', token: `wrong-${i}`, new_password: 'newpass1' })
      expect(res.status).toBe(401)
    }

    const sixth = await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'alice@test.local', token: 'wrong-6', new_password: 'newpass1' })
    expect(sixth.status).toBe(429)
  })

  test("a different email's budget is unaffected by the first email's usage", async () => {
    const app = newTestApp({ confirmRateLimit: 1, confirmRateWindowSeconds: 300 })
    await request(app).post('/forgot-password').send({ email: 'alice@test.local' })
    await request(app).post('/forgot-password').send({ email: 'bob@test.local' })

    await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'alice@test.local', token: 'wrong', new_password: 'newpass1' })
    const aliceSecond = await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'alice@test.local', token: 'wrong2', new_password: 'newpass1' })
    expect(aliceSecond.status).toBe(429)

    const bobFirst = await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'bob@test.local', token: 'wrong', new_password: 'newpass1' })
    expect(bobFirst.status).toBe(401)
  })

  test('further attempts are allowed again once the rate-limit window elapses', async () => {
    const app = newTestApp({ confirmRateLimit: 1, confirmRateWindowSeconds: 1 })
    await request(app).post('/forgot-password').send({ email: 'alice@test.local' })

    await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'alice@test.local', token: 'wrong', new_password: 'newpass1' })
    const throttled = await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'alice@test.local', token: 'wrong2', new_password: 'newpass1' })
    expect(throttled.status).toBe(429)

    await new Promise((resolve) => setTimeout(resolve, 1100))

    const afterWindow = await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'alice@test.local', token: 'wrong3', new_password: 'newpass1' })
    expect(afterWindow.status).toBe(401)
  })
})

describe('per-email throttling on /forgot-password', () => {
  test('a throwaway self-test account gets its own independent budget from a real target', async () => {
    const app = newTestApp({ confirmRateLimit: 1, confirmRateWindowSeconds: 300 })
    await request(app).post('/forgot-password').send({ email: 'throwaway@test.local' })
    const throwawayRes = await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'throwaway@test.local', token: 'wrong', new_password: 'newpass1' })
    expect(throwawayRes.status).toBe(401)

    await request(app).post('/forgot-password').send({ email: 'admin@foundry.local' })
    const adminRes = await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'admin@foundry.local', token: 'wrong', new_password: 'newpass1' })
    expect(adminRes.status).toBe(401)
  })
})
