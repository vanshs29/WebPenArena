const request = require('supertest')
const { newTestApp, loginAs } = require('./helpers')

describe('registration and login', () => {
  let app
  beforeEach(() => {
    app = newTestApp()
  })

  test('register creates an employee account', async () => {
    const res = await request(app).post('/register').send({ username: 'carol', password: 'Pass1234' })
    expect([200, 201, 302]).toContain(res.status)
  })

  test('register ignores a supplied role', async () => {
    await request(app).post('/register').send({ username: 'eve', password: 'Pass1234', role: 'admin' })
    const cookie = await loginAs(app, 'eve', 'Pass1234')
    const res = await request(app).get('/admin').set('Cookie', cookie)
    expect(res.status).toBe(403)
  })

  test('login with valid seed credentials succeeds', async () => {
    const res = await request(app).post('/login').send({ username: 'alice', password: 'password123' })
    expect(res.status).toBe(200)
    expect(res.headers['set-cookie']).toBeDefined()
  })

  test('login with wrong password fails', async () => {
    const res = await request(app).post('/login').send({ username: 'alice', password: 'wrong' })
    expect(res.status).toBe(401)
  })

  test('duplicate username registration fails', async () => {
    await request(app).post('/register').send({ username: 'dup', password: 'Pass1234' })
    const res = await request(app).post('/register').send({ username: 'dup', password: 'Pass1234' })
    expect(res.status).toBe(409)
  })

  test('register with missing password fails', async () => {
    const res = await request(app).post('/register').send({ username: 'nopass' })
    expect(res.status).toBe(400)
  })

  test('register with missing username fails', async () => {
    const res = await request(app).post('/register').send({ password: 'Pass1234' })
    expect(res.status).toBe(400)
  })

  test('login with missing password fails', async () => {
    const res = await request(app).post('/login').send({ username: 'alice' })
    expect(res.status).toBe(401)
  })

  test('login with unknown username fails', async () => {
    const res = await request(app).post('/login').send({ username: 'nobody', password: 'x' })
    expect(res.status).toBe(401)
  })

  test('admin credentials are never guessable through login', async () => {
    const res = await request(app).post('/login').send({ username: 'admin', password: 'admin' })
    expect(res.status).toBe(401)
  })
})
