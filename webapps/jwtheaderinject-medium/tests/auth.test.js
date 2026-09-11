const request = require('supertest')
const jwt = require('jsonwebtoken')
const { newTestApp, registerAndLogin } = require('./helpers')

describe('registration', () => {
  test('creates a user and exactly one real order', async () => {
    const app = newTestApp()
    const res = await request(app)
      .post('/register')
      .send({ username: 'alice', email: 'alice@test.local', password: 'password123' })
    expect(res.status).toBe(201)

    const db = app.locals.db
    const user = db.prepare('SELECT id FROM users WHERE email = ?').get('alice@test.local')
    const orders = db.prepare('SELECT * FROM orders WHERE user_id = ?').all(user.id)
    expect(orders).toHaveLength(1)
    expect(orders[0].description).toBe('Starter Plan Subscription')
    expect(orders[0].amount).toBe(49.0)
    expect(orders[0].status).toBe('paid')
  })

  test('rejects a duplicate email with 409', async () => {
    const app = newTestApp()
    await request(app).post('/register').send({ username: 'alice', email: 'alice@test.local', password: 'password123' })
    const res = await request(app).post('/register').send({ username: 'alice2', email: 'alice@test.local', password: 'password123' })
    expect(res.status).toBe(409)
  })

  test('rejects a missing password with 400', async () => {
    const app = newTestApp()
    const res = await request(app).post('/register').send({ username: 'alice', email: 'alice@test.local' })
    expect(res.status).toBe(400)
  })
})

describe('login', () => {
  test('issues a session cookie whose token verifies as RS256', async () => {
    const app = newTestApp()
    await request(app).post('/register').send({ username: 'alice', email: 'alice@test.local', password: 'password123' })
    const res = await request(app).post('/login').send({ email: 'alice@test.local', password: 'password123' })
    expect(res.status).toBe(200)
    const cookie = res.headers['set-cookie'][0]
    const token = cookie.split('session=')[1].split(';')[0]
    const decoded = jwt.verify(token, app.locals.sessionPublicKey, { algorithms: ['RS256'] })
    expect(decoded.sub).toBeDefined()
  })

  test('rejects wrong password with 401', async () => {
    const app = newTestApp()
    await request(app).post('/register').send({ username: 'alice', email: 'alice@test.local', password: 'password123' })
    const res = await request(app).post('/login').send({ email: 'alice@test.local', password: 'wrong' })
    expect(res.status).toBe(401)
  })

  test('rejects an unknown email with 401', async () => {
    const app = newTestApp()
    const res = await request(app).post('/login').send({ email: 'nobody@test.local', password: 'password123' })
    expect(res.status).toBe(401)
  })

  test('does not create an additional order on repeat login', async () => {
    const app = newTestApp()
    await registerAndLogin(app)
    const db = app.locals.db
    const user = db.prepare('SELECT id FROM users WHERE email = ?').get('alice@test.local')
    const orders = db.prepare('SELECT * FROM orders WHERE user_id = ?').all(user.id)
    expect(orders).toHaveLength(1)
  })
})

describe('GET /orders', () => {
  test('requires auth', async () => {
    const app = newTestApp()
    const res = await request(app).get('/orders')
    expect(res.status).toBe(401)
  })

  test('shows only the caller\'s own order, not another account\'s', async () => {
    const app = newTestApp()
    const cookieA = await registerAndLogin(app, 'alice@test.local', 'password123', 'alice')
    await registerAndLogin(app, 'bob@test.local', 'password123', 'bob')

    const db = app.locals.db
    const bob = db.prepare('SELECT id FROM users WHERE email = ?').get('bob@test.local')
    const bobOrder = db.prepare('SELECT id FROM orders WHERE user_id = ?').get(bob.id)
    const alice = db.prepare('SELECT id FROM users WHERE email = ?').get('alice@test.local')
    const aliceOrder = db.prepare('SELECT id FROM orders WHERE user_id = ?').get(alice.id)

    const resA = await request(app).get('/orders').set('Cookie', cookieA)
    expect(resA.status).toBe(200)
    expect(resA.text).toContain(`>${aliceOrder.id}<`)
    expect(resA.text).not.toContain(`>${bobOrder.id}<`)
  })
})
