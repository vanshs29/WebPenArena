const request = require('supertest')
const { newTestApp, registerAndLogin } = require('./helpers')

test('N concurrent redemptions with distinct keys all credit the same code', async () => {
  const app = newTestApp(30)
  const cookie = await registerAndLogin(app)
  const N = 10
  const requests = Array.from({ length: N }, (_, i) =>
    request(app).post('/wallet/redeem').set('Cookie', cookie)
      .send({ code: 'WELCOME50', idempotency_key: `key-${i}` })
  )
  await Promise.all(requests)
  await new Promise((r) => setTimeout(r, 100))
  const wallet = await request(app).get('/wallet').set('Cookie', cookie).set('Accept', 'application/json')
  expect(wallet.body.balance).toBe(N * 50)
})

test('a single sequential redemption never exceeds one credit', async () => {
  const app = newTestApp(30)
  const cookie = await registerAndLogin(app)
  await request(app).post('/wallet/redeem').set('Cookie', cookie)
    .send({ code: 'WELCOME50', idempotency_key: 'only-key' })
  await new Promise((r) => setTimeout(r, 60))
  const wallet = await request(app).get('/wallet').set('Cookie', cookie).set('Accept', 'application/json')
  expect(wallet.body.balance).toBe(50)
})
