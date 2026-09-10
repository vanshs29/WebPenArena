const jwt = require('jsonwebtoken')
const request = require('supertest')
const { newTestApp, loginAs } = require('./helpers')

describe('registration', () => {
  let app
  beforeEach(() => {
    app = newTestApp()
  })

  test('registration always assigns role member regardless of a supplied role field', async () => {
    const res = await request(app)
      .post('/register')
      .send({ username: 'carol', password: 'Pass1234', role: 'admin' })
    expect([200, 201]).toContain(res.status)

    const cookie = await loginAs(app, 'carol', 'Pass1234')
    const decoded = jwt.decode(cookie.split('=')[1])
    expect(decoded.role).toBe('member')
  })

  test('registering an existing username fails', async () => {
    await request(app).post('/register').send({ username: 'alice', password: 'x' })
    const res = await request(app).post('/register').send({ username: 'alice', password: 'y' })
    expect(res.status).toBe(409)
  })
})

describe('login', () => {
  let app
  beforeEach(() => {
    app = newTestApp()
  })

  test('valid seed credentials succeed and set an RS256 session cookie', async () => {
    const res = await request(app).post('/login').send({ username: 'alice', password: 'password123' })
    expect(res.status).toBe(200)
    const cookie = res.headers['set-cookie'][0].split(';')[0]
    const token = cookie.split('=')[1]
    const decoded = jwt.decode(token, { complete: true })
    expect(decoded.header.alg).toBe('RS256')
  })

  test('wrong password is rejected', async () => {
    const res = await request(app).post('/login').send({ username: 'alice', password: 'wrong' })
    expect(res.status).toBe(401)
  })

  test('unknown username is rejected', async () => {
    const res = await request(app).post('/login').send({ username: 'nobody', password: 'x' })
    expect(res.status).toBe(401)
  })
})
