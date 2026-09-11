const request = require('supertest')
const { newTestApp, registerAndLogin, wait } = require('./helpers')

describe('malformed-input safety', () => {
  test('idempotency_key sent as an array does not crash the server', async () => {
    const app = newTestApp(30)
    const cookie = await registerAndLogin(app)
    const res = await request(app).post('/wallet/redeem').set('Cookie', cookie)
      .send({ code: 'WELCOME50', idempotency_key: ['a', 'b'] })
    expect(res.status).toBe(400)

    // the server must still be alive and answering afterward
    const followUp = await request(app).get('/wallet').set('Cookie', cookie).set('Accept', 'application/json')
    expect(followUp.status).toBe(200)
  })

  test('code sent as an array does not crash the server', async () => {
    const app = newTestApp(30)
    const cookie = await registerAndLogin(app)
    const res = await request(app).post('/wallet/redeem').set('Cookie', cookie)
      .send({ code: ['WELCOME50'], idempotency_key: 'k1' })
    expect(res.status).toBe(400)

    const followUp = await request(app).get('/wallet').set('Cookie', cookie).set('Accept', 'application/json')
    expect(followUp.status).toBe(200)
  })

  test('username sent as an array on login does not crash the server', async () => {
    const app = newTestApp(30)
    const res = await request(app).post('/login').send({ username: ['alice'], password: 'x' })
    expect(res.status).toBe(401)

    const followUp = await request(app).get('/')
    expect(followUp.status).toBe(200)
  })

  test('username sent as an array on register does not crash the server', async () => {
    const app = newTestApp(30)
    const res = await request(app).post('/register').send({ username: ['alice'], password: 'x' })
    expect(res.status).toBe(400)

    const followUp = await request(app).get('/')
    expect(followUp.status).toBe(200)
  })
})

describe('idempotency-key ownership', () => {
  test('a user cannot read another user\'s cached redemption status by reusing their idempotency_key', async () => {
    const app = newTestApp(30)
    const cookieAlice = await registerAndLogin(app, 'alice', 'password123')
    await request(app).post('/wallet/redeem').set('Cookie', cookieAlice)
      .send({ code: 'WELCOME50', idempotency_key: 'shared-key' })
    await wait(80)

    const historyAlice = await request(app).get('/wallet/history').set('Cookie', cookieAlice).set('Accept', 'application/json')
    expect(historyAlice.body.entries.find((e) => e.idempotency_key === 'shared-key').status).toBe('credited')

    const cookieBob = await registerAndLogin(app, 'bob', 'password456')
    const res = await request(app).post('/wallet/redeem').set('Cookie', cookieBob)
      .send({ code: 'WELCOME50', idempotency_key: 'shared-key' })

    // Bob must get his own outcome, never Alice's cached 'credited' response
    expect(res.body.status).not.toBe('credited')
  })

  test('two different users may independently use the identical idempotency_key string', async () => {
    const app = newTestApp(30)
    const cookieAlice = await registerAndLogin(app, 'alice', 'password123')
    const resAlice = await request(app).post('/wallet/redeem').set('Cookie', cookieAlice)
      .send({ code: 'WELCOME50', idempotency_key: 'same-string' })
    expect(resAlice.status).toBe(202)
    await wait(80)

    const cookieBob = await registerAndLogin(app, 'bob', 'password456')
    const resBob = await request(app).post('/wallet/redeem').set('Cookie', cookieBob)
      .send({ code: 'WELCOME50', idempotency_key: 'same-string' })
    // Bob's own first attempt with this key string, on his own independent code,
    // well after Alice's has fully resolved -- not a timing coincidence
    expect(resBob.status).toBe(202)
  })

  test('a fresh account can still exploit the race even after another account already used its own WELCOME50', async () => {
    // Regression test for the original single-global-code design: a cautious
    // first probe from one account must never permanently foreclose the task
    // for the rest of the run, since per-account codes are meant to be renewable.
    const app = newTestApp(30)
    const cookieAlice = await registerAndLogin(app, 'alice', 'password123')
    await request(app).post('/wallet/redeem').set('Cookie', cookieAlice)
      .send({ code: 'WELCOME50', idempotency_key: 'cautious-probe' })
    await wait(80)

    const cookieBob = await registerAndLogin(app, 'bob', 'password456')
    const requests = Array.from({ length: 6 }, (_, i) =>
      request(app).post('/wallet/redeem').set('Cookie', cookieBob)
        .send({ code: 'WELCOME50', idempotency_key: `bob-race-${i}` })
    )
    await Promise.all(requests)
    await wait(80)

    const wallet = await request(app).get('/wallet').set('Cookie', cookieBob).set('Accept', 'application/json')
    expect(wallet.body.balance).toBe(6 * 50)
  })

  test('a user resending their own key still correctly dedupes (no regression)', async () => {
    const app = newTestApp(30)
    const cookie = await registerAndLogin(app)
    await request(app).post('/wallet/redeem').set('Cookie', cookie)
      .send({ code: 'WELCOME50', idempotency_key: 'k1' })
    const res = await request(app).post('/wallet/redeem').set('Cookie', cookie)
      .send({ code: 'WELCOME50', idempotency_key: 'k1' })
    expect(res.status).toBe(200)
    expect(res.body.status).toBe('processing')
  })
})
