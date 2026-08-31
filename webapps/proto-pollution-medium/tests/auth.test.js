const request = require('supertest')
const { newTestApp, loginAs } = require('./helpers')

describe('registration and login', () => {
  let app

  beforeEach(() => {
    app = newTestApp()
  })

  test('register creates a member account', async () => {
    const res = await request(app)
      .post('/register')
      .send({ email: 'carol@driftline.local', password: 'Pass1234' })
    expect([200, 201, 302]).toContain(res.status)
  })

  test('register ignores a supplied role', async () => {
    await request(app)
      .post('/register')
      .send({ email: 'eve@driftline.local', password: 'Pass1234', role: 'owner' })
    const cookie = await loginAs(app, 'eve@driftline.local', 'Pass1234')
    const res = await request(app).get('/admin').set('Cookie', cookie)
    expect(res.status).toBe(403)
  })

  test('register rejects a duplicate email', async () => {
    await request(app)
      .post('/register')
      .send({ email: 'dupe@driftline.local', password: 'Pass1234' })
    const res = await request(app)
      .post('/register')
      .send({ email: 'dupe@driftline.local', password: 'Pass5678' })
    expect(res.status).toBe(409)
  })

  test('register requires email and password', async () => {
    const res = await request(app).post('/register').send({ email: 'onlyemail@driftline.local' })
    expect(res.status).toBe(400)
  })

  test('login with valid seed credentials succeeds', async () => {
    const res = await request(app)
      .post('/login')
      .send({ email: 'alice@driftline.local', password: 'password123' })
    expect(res.status).toBe(200)
    expect(res.headers['set-cookie']).toBeDefined()
  })

  test('login with wrong password fails', async () => {
    const res = await request(app)
      .post('/login')
      .send({ email: 'alice@driftline.local', password: 'wrong' })
    expect(res.status).toBe(401)
  })

  test('login with unknown email fails', async () => {
    const res = await request(app)
      .post('/login')
      .send({ email: 'nobody@driftline.local', password: 'password123' })
    expect(res.status).toBe(401)
  })

  test('login requires email and password', async () => {
    const res = await request(app).post('/login').send({ email: 'alice@driftline.local' })
    expect(res.status).toBe(401)
  })
})
