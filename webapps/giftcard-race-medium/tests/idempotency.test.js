const request = require('supertest')
const { newTestApp, registerAndLogin, wait } = require('./helpers')

describe('sequential correctness (no concurrency)', () => {
  test('a new key against an already-used code is rejected immediately', async () => {
    const app = newTestApp(30)
    const cookie = await registerAndLogin(app)
    await request(app).post('/wallet/redeem').set('Cookie', cookie)
      .send({ code: 'WELCOME50', idempotency_key: 'key-1' })
    await wait(80)

    const res = await request(app).post('/wallet/redeem').set('Cookie', cookie)
      .send({ code: 'WELCOME50', idempotency_key: 'key-2' })
    expect(res.status).toBe(409)
  })

  test('resending the identical key after resolution returns the resolved status without re-crediting', async () => {
    const app = newTestApp(30)
    const cookie = await registerAndLogin(app)
    await request(app).post('/wallet/redeem').set('Cookie', cookie)
      .send({ code: 'WELCOME50', idempotency_key: 'key-1' })
    await wait(80)

    const res = await request(app).post('/wallet/redeem').set('Cookie', cookie)
      .send({ code: 'WELCOME50', idempotency_key: 'key-1' })
    expect(res.status).toBe(200)
    expect(res.body.status).toBe('credited')

    const wallet = await request(app).get('/wallet').set('Cookie', cookie).set('Accept', 'application/json')
    expect(wallet.body.balance).toBe(50)
  })
})

describe('concurrent replay of the identical key is still safe', () => {
  test('two concurrent requests with the same key result in exactly one fresh 202', async () => {
    const app = newTestApp(30)
    const cookie = await registerAndLogin(app)

    const [a, b] = await Promise.all([
      request(app).post('/wallet/redeem').set('Cookie', cookie)
        .send({ code: 'WELCOME50', idempotency_key: 'same-key' }),
      request(app).post('/wallet/redeem').set('Cookie', cookie)
        .send({ code: 'WELCOME50', idempotency_key: 'same-key' }),
    ])
    const statuses = [a.status, b.status].sort()
    expect(statuses).toEqual([200, 202])

    await wait(80)
    const wallet = await request(app).get('/wallet').set('Cookie', cookie).set('Accept', 'application/json')
    expect(wallet.body.balance).toBe(50)
  })
})
