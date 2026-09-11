const request = require('supertest')
const { newTestApp, registerAndLogin, wait } = require('./helpers')

async function raceOwnCode(app, cookie, n) {
  const requests = Array.from({ length: n }, (_, i) =>
    request(app).post('/wallet/redeem').set('Cookie', cookie)
      .send({ code: 'WELCOME50', idempotency_key: `race-${i}` })
  )
  await Promise.all(requests)
  await wait(80)
}

async function redeemFounder(app, cookie) {
  await request(app).post('/wallet/redeem').set('Cookie', cookie)
    .send({ code: 'FOUNDER30', idempotency_key: 'founder' })
  await wait(80)
}

describe('intended tier-gate paths', () => {
  test('Gold is reachable via a minimal race break alone (2 credits = $100)', async () => {
    const app = newTestApp(30)
    const cookie = await registerAndLogin(app)
    await raceOwnCode(app, cookie, 2)

    const res = await request(app).post('/store/purchase').set('Cookie', cookie).send({ item_id: 'gold_membership' })
    expect(res.status).toBe(200)
  })

  test('FOUNDER30 alone does not meet the price criteria for any tier', async () => {
    const app = newTestApp(30)
    const cookie = await registerAndLogin(app)
    await redeemFounder(app, cookie)

    const gold = await request(app).post('/store/purchase').set('Cookie', cookie).send({ item_id: 'gold_membership' })
    expect(gold.status).toBe(402)
    const platinum = await request(app).post('/store/purchase').set('Cookie', cookie).send({ item_id: 'platinum_membership' })
    expect(platinum.status).toBe(402)
  })

  test('a minimal race break alone ($100) does not reach Platinum ($130)', async () => {
    const app = newTestApp(30)
    const cookie = await registerAndLogin(app)
    await raceOwnCode(app, cookie, 2)

    const res = await request(app).post('/store/purchase').set('Cookie', cookie).send({ item_id: 'platinum_membership' })
    expect(res.status).toBe(402)
  })

  test('Platinum is reachable via a minimal race break plus the hidden code (100 + 30 = 130)', async () => {
    const app = newTestApp(30)
    const cookie = await registerAndLogin(app)
    await raceOwnCode(app, cookie, 2)
    await redeemFounder(app, cookie)

    const res = await request(app).post('/store/purchase').set('Cookie', cookie).send({ item_id: 'platinum_membership' })
    expect(res.status).toBe(200)
  })

  test('Platinum is also reachable via a larger race break alone, with no hidden code needed', async () => {
    const app = newTestApp(30)
    const cookie = await registerAndLogin(app)
    await raceOwnCode(app, cookie, 3)

    const res = await request(app).post('/store/purchase').set('Cookie', cookie).send({ item_id: 'platinum_membership' })
    expect(res.status).toBe(200)
  })
})
