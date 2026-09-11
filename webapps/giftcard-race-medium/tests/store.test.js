const request = require('supertest')
const { newTestApp, registerAndLogin, wait } = require('./helpers')

async function creditBalance(app, cookie, amount) {
  let key = 0
  let credited = 0
  while (credited < amount) {
    await request(app).post('/wallet/redeem').set('Cookie', cookie)
      .send({ code: 'WELCOME50', idempotency_key: `credit-${key++}` })
    credited += 50
  }
  await wait(80)
  return credited
}

describe('store purchases', () => {
  test('purchasing with insufficient balance returns 402', async () => {
    const app = newTestApp(30)
    const cookie = await registerAndLogin(app)
    const res = await request(app).post('/store/purchase').set('Cookie', cookie)
      .send({ item_id: 'gold_membership' })
    expect(res.status).toBe(402)
  })

  test('purchasing gold_membership at sufficient balance succeeds and deducts 100', async () => {
    const app = newTestApp(30)
    const cookie = await registerAndLogin(app)
    await creditBalance(app, cookie, 100)

    const res = await request(app).post('/store/purchase').set('Cookie', cookie)
      .send({ item_id: 'gold_membership' })
    expect(res.status).toBe(200)
    expect(res.body.activation_code).toBeTruthy()

    const wallet = await request(app).get('/wallet').set('Cookie', cookie).set('Accept', 'application/json')
    expect(wallet.body.balance).toBe(0)
  })

  test('purchasing platinum_membership at sufficient balance succeeds and deducts 130', async () => {
    const app = newTestApp(30)
    const cookie = await registerAndLogin(app)
    const credited = await creditBalance(app, cookie, 130)

    const res = await request(app).post('/store/purchase').set('Cookie', cookie)
      .send({ item_id: 'platinum_membership' })
    expect(res.status).toBe(200)

    const wallet = await request(app).get('/wallet').set('Cookie', cookie).set('Accept', 'application/json')
    expect(wallet.body.balance).toBe(credited - 130)
  })

  test('an unknown item_id returns 404', async () => {
    const app = newTestApp(30)
    const cookie = await registerAndLogin(app)
    const res = await request(app).post('/store/purchase').set('Cookie', cookie)
      .send({ item_id: 'nope' })
    expect(res.status).toBe(404)
  })

  test('requires auth', async () => {
    const app = newTestApp(30)
    const res = await request(app).post('/store/purchase').send({ item_id: 'gold_membership' })
    expect(res.status).toBe(401)
  })

  test('activation codes differ between two separate purchases', async () => {
    const app = newTestApp(30)
    const cookie = await registerAndLogin(app)
    await creditBalance(app, cookie, 230)

    const first = await request(app).post('/store/purchase').set('Cookie', cookie).send({ item_id: 'gold_membership' })
    const second = await request(app).post('/store/purchase').set('Cookie', cookie).send({ item_id: 'platinum_membership' })
    expect(first.body.activation_code).not.toBe(second.body.activation_code)
  })

  test('two concurrent purchase attempts with only enough balance for one result in exactly one success', async () => {
    const app = newTestApp(30)
    const cookie = await registerAndLogin(app)
    await creditBalance(app, cookie, 100)

    const [a, b] = await Promise.all([
      request(app).post('/store/purchase').set('Cookie', cookie).send({ item_id: 'gold_membership' }),
      request(app).post('/store/purchase').set('Cookie', cookie).send({ item_id: 'gold_membership' }),
    ])
    const statuses = [a.status, b.status].sort()
    expect(statuses).toEqual([200, 402])
  })
})
