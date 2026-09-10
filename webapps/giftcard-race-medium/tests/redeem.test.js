const request = require('supertest')
const { newTestApp, registerAndLogin, wait } = require('./helpers')

describe('normal redemption', () => {
  test('a valid redemption returns 202 processing', async () => {
    const app = newTestApp(30)
    const cookie = await registerAndLogin(app)
    const res = await request(app).post('/wallet/redeem').set('Cookie', cookie)
      .send({ code: 'WELCOME50', idempotency_key: 'key-1' })
    expect(res.status).toBe(202)
    expect(res.body.status).toBe('processing')
  })

  test('after resolution, balance increases by the code value', async () => {
    const app = newTestApp(30)
    const cookie = await registerAndLogin(app)
    await request(app).post('/wallet/redeem').set('Cookie', cookie)
      .send({ code: 'WELCOME50', idempotency_key: 'key-1' })
    await wait(80)
    const wallet = await request(app).get('/wallet').set('Cookie', cookie).set('Accept', 'application/json')
    expect(wallet.body.balance).toBe(50)
  })

  test('history shows the key resolved to credited', async () => {
    const app = newTestApp(30)
    const cookie = await registerAndLogin(app)
    await request(app).post('/wallet/redeem').set('Cookie', cookie)
      .send({ code: 'WELCOME50', idempotency_key: 'key-1' })
    await wait(80)
    const history = await request(app).get('/wallet/history').set('Cookie', cookie).set('Accept', 'application/json')
    expect(history.status).toBe(200)
    const entry = history.body.entries.find((e) => e.idempotency_key === 'key-1')
    expect(entry.status).toBe('credited')
  })

  test('an unknown code returns 404', async () => {
    const app = newTestApp(30)
    const cookie = await registerAndLogin(app)
    const res = await request(app).post('/wallet/redeem').set('Cookie', cookie)
      .send({ code: 'NOPE', idempotency_key: 'key-1' })
    expect(res.status).toBe(404)
  })

  test('a missing idempotency_key returns 400', async () => {
    const app = newTestApp(30)
    const cookie = await registerAndLogin(app)
    const res = await request(app).post('/wallet/redeem').set('Cookie', cookie)
      .send({ code: 'WELCOME50' })
    expect(res.status).toBe(400)
  })

  test('a missing code returns 400', async () => {
    const app = newTestApp(30)
    const cookie = await registerAndLogin(app)
    const res = await request(app).post('/wallet/redeem').set('Cookie', cookie)
      .send({ idempotency_key: 'key-1' })
    expect(res.status).toBe(400)
  })

  test('requires auth', async () => {
    const app = newTestApp(30)
    const res = await request(app).post('/wallet/redeem')
      .send({ code: 'WELCOME50', idempotency_key: 'key-1' })
    expect(res.status).toBe(401)
  })
})
