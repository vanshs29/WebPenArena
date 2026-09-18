const request = require('supertest')
const { newTestApp } = require('./helpers')

describe('registration and login', () => {
  let app

  beforeEach(() => {
    app = newTestApp()
  })

  it('registers a new user with a unique email and username', async () => {
    const res = await request(app)
      .post('/register')
      .send({ username: 'bob', email: 'bob@test.local', password: 'hunter2' })
    expect(res.status).toBe(201)
  })

  it('rejects registration with a duplicate email', async () => {
    await request(app)
      .post('/register')
      .send({ username: 'bob', email: 'bob@test.local', password: 'hunter2' })
    const res = await request(app)
      .post('/register')
      .send({ username: 'bob2', email: 'bob@test.local', password: 'hunter2' })
    expect(res.status).toBe(409)
  })

  it('rejects registration with a duplicate username', async () => {
    await request(app)
      .post('/register')
      .send({ username: 'bob', email: 'bob@test.local', password: 'hunter2' })
    const res = await request(app)
      .post('/register')
      .send({ username: 'bob', email: 'bob2@test.local', password: 'hunter2' })
    expect(res.status).toBe(409)
  })

  it('logs in with valid credentials and sets a session cookie', async () => {
    await request(app)
      .post('/register')
      .send({ username: 'bob', email: 'bob@test.local', password: 'hunter2' })
    const res = await request(app).post('/login').send({ email: 'bob@test.local', password: 'hunter2' })
    expect(res.status).toBe(200)
    expect(res.headers['set-cookie'][0]).toMatch(/session=/)
  })

  it('rejects login with the wrong password', async () => {
    await request(app)
      .post('/register')
      .send({ username: 'bob', email: 'bob@test.local', password: 'hunter2' })
    const res = await request(app).post('/login').send({ email: 'bob@test.local', password: 'wrong' })
    expect(res.status).toBe(401)
  })

  it('rejects login for an unregistered email', async () => {
    const res = await request(app).post('/login').send({ email: 'nobody@test.local', password: 'x' })
    expect(res.status).toBe(401)
  })

  it('requires authentication for /account', async () => {
    const res = await request(app).get('/account')
    expect(res.status).toBe(401)
  })

  it('allows /account when authenticated', async () => {
    await request(app)
      .post('/register')
      .send({ username: 'bob', email: 'bob@test.local', password: 'hunter2' })
    const loginRes = await request(app).post('/login').send({ email: 'bob@test.local', password: 'hunter2' })
    const cookie = loginRes.headers['set-cookie'][0].split(';')[0]
    const res = await request(app).get('/account').set('Cookie', cookie)
    expect(res.status).toBe(200)
  })
})
