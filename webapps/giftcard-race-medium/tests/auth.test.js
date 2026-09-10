const request = require('supertest')
const { newTestApp } = require('./helpers')

describe('registration', () => {
  test('a valid registration succeeds', async () => {
    const app = newTestApp()
    const res = await request(app).post('/register').send({ username: 'alice', password: 'password123' })
    expect(res.status).toBe(201)
  })

  test('rejects duplicate usernames', async () => {
    const app = newTestApp()
    await request(app).post('/register').send({ username: 'alice', password: 'password123' })
    const res = await request(app).post('/register').send({ username: 'alice', password: 'other' })
    expect(res.status).toBe(409)
  })

  test('rejects missing fields', async () => {
    const app = newTestApp()
    const res = await request(app).post('/register').send({ username: 'alice' })
    expect(res.status).toBe(400)
  })
})

describe('login', () => {
  test('valid credentials succeed and set a session cookie', async () => {
    const app = newTestApp()
    await request(app).post('/register').send({ username: 'alice', password: 'password123' })
    const res = await request(app).post('/login').send({ username: 'alice', password: 'password123' })
    expect(res.status).toBe(200)
    expect(res.headers['set-cookie'][0]).toMatch(/session=/)
  })

  test('wrong password is rejected', async () => {
    const app = newTestApp()
    await request(app).post('/register').send({ username: 'alice', password: 'password123' })
    const res = await request(app).post('/login').send({ username: 'alice', password: 'wrong' })
    expect(res.status).toBe(401)
  })

  test('unknown username is rejected', async () => {
    const app = newTestApp()
    const res = await request(app).post('/login').send({ username: 'nobody', password: 'x' })
    expect(res.status).toBe(401)
  })
})
