const request = require('supertest')
const { newTestApp } = require('./helpers')

describe('registration', () => {
  test('creates a user and auto-joins workspace 1 as member', async () => {
    const app = newTestApp()
    const res = await request(app)
      .post('/register')
      .send({ email: 'bob@test.local', password: 'pw123456' })
    expect(res.status).toBe(201)

    const db = app.locals.db
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get('bob@test.local')
    expect(user).toBeTruthy()
    const membership = db
      .prepare('SELECT * FROM memberships WHERE user_id = ? AND workspace_id = 1')
      .get(user.id)
    expect(membership).toBeTruthy()
    expect(membership.role).toBe('member')
  })

  test('rejects a duplicate email with 409', async () => {
    const app = newTestApp()
    await request(app).post('/register').send({ email: 'bob@test.local', password: 'pw123456' })
    const res = await request(app)
      .post('/register')
      .send({ email: 'bob@test.local', password: 'other' })
    expect(res.status).toBe(409)
  })

  test('rejects a missing password with 400', async () => {
    const app = newTestApp()
    const res = await request(app).post('/register').send({ email: 'bob@test.local' })
    expect(res.status).toBe(400)
  })
})

describe('login', () => {
  test('valid credentials succeed and set a session cookie', async () => {
    const app = newTestApp()
    await request(app).post('/register').send({ email: 'bob@test.local', password: 'pw123456' })
    const res = await request(app)
      .post('/login')
      .send({ email: 'bob@test.local', password: 'pw123456' })
    expect(res.status).toBe(200)
    expect(res.headers['set-cookie'][0]).toMatch(/^session=/)
  })

  test('wrong password returns 401', async () => {
    const app = newTestApp()
    await request(app).post('/register').send({ email: 'bob@test.local', password: 'pw123456' })
    const res = await request(app)
      .post('/login')
      .send({ email: 'bob@test.local', password: 'wrong' })
    expect(res.status).toBe(401)
  })

  test('unknown email returns 401', async () => {
    const app = newTestApp()
    const res = await request(app)
      .post('/login')
      .send({ email: 'nobody@test.local', password: 'pw123456' })
    expect(res.status).toBe(401)
  })
})
