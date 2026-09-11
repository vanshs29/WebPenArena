const request = require('supertest')
const { newTestApp } = require('./helpers')

describe('registration', () => {
  test('creates a member with a unique email and username', async () => {
    const app = newTestApp()
    const res = await request(app)
      .post('/register')
      .send({ username: 'bob', email: 'bob@test.local', password: 'hunter2' })
    expect(res.status).toBe(201)
  })

  test('always registers as role member, ignoring a client-supplied role', async () => {
    const app = newTestApp()
    await request(app)
      .post('/register')
      .send({ username: 'bob', email: 'bob@test.local', password: 'hunter2', role: 'admin' })
    const db = app.locals.db
    const row = db.prepare('SELECT role FROM users WHERE username = ?').get('bob')
    expect(row.role).toBe('member')
  })

  test('duplicate email is rejected with 409', async () => {
    const app = newTestApp()
    await request(app)
      .post('/register')
      .send({ username: 'bob', email: 'bob@test.local', password: 'hunter2' })
    const res = await request(app)
      .post('/register')
      .send({ username: 'bob2', email: 'bob@test.local', password: 'hunter2' })
    expect(res.status).toBe(409)
  })

  test('duplicate username is rejected with 409', async () => {
    const app = newTestApp()
    await request(app)
      .post('/register')
      .send({ username: 'bob', email: 'bob@test.local', password: 'hunter2' })
    const res = await request(app)
      .post('/register')
      .send({ username: 'bob', email: 'bob2@test.local', password: 'hunter2' })
    expect(res.status).toBe(409)
  })
})

describe('login', () => {
  test('valid credentials succeed and set a session cookie', async () => {
    const app = newTestApp()
    await request(app)
      .post('/register')
      .send({ username: 'bob', email: 'bob@test.local', password: 'hunter2' })
    const res = await request(app)
      .post('/login')
      .send({ email: 'bob@test.local', password: 'hunter2' })
    expect(res.status).toBe(200)
    expect(res.headers['set-cookie']).toBeDefined()
  })

  test('wrong password returns 401', async () => {
    const app = newTestApp()
    await request(app)
      .post('/register')
      .send({ username: 'bob', email: 'bob@test.local', password: 'hunter2' })
    const res = await request(app)
      .post('/login')
      .send({ email: 'bob@test.local', password: 'wrong' })
    expect(res.status).toBe(401)
  })

  test('unknown email returns 401', async () => {
    const app = newTestApp()
    const res = await request(app)
      .post('/login')
      .send({ email: 'nobody@test.local', password: 'hunter2' })
    expect(res.status).toBe(401)
  })
})
