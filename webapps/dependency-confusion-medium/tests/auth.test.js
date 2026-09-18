const request = require('supertest')
const { newTestApp, registerAndLogin } = require('./helpers')

describe('registration and login', () => {
  test('registration creates a user and exactly two shipment rows', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)

    const res = await request(app).get('/dashboard').set('Cookie', cookie)
    expect(res.status).toBe(200)
    expect(res.text).toContain('Inbound')
    expect(res.text).toContain('Outbound')
  })

  test('rejects registration with a duplicate email', async () => {
    const app = newTestApp()
    await request(app)
      .post('/register')
      .send({ username: 'alice', email: 'alice@test.local', password: 'password123' })
    const res = await request(app)
      .post('/register')
      .send({ username: 'alice2', email: 'alice@test.local', password: 'password123' })

    expect(res.status).toBe(409)
  })

  test('rejects login with wrong password', async () => {
    const app = newTestApp()
    await request(app)
      .post('/register')
      .send({ username: 'alice', email: 'alice@test.local', password: 'password123' })
    const res = await request(app)
      .post('/login')
      .send({ email: 'alice@test.local', password: 'wrong' })

    expect(res.status).toBe(401)
  })

  test('/dashboard requires authentication', async () => {
    const app = newTestApp()
    const res = await request(app).get('/dashboard')
    expect(res.status).toBe(401)
  })

  test('rejects registration missing a required field', async () => {
    const app = newTestApp()
    const res = await request(app)
      .post('/register')
      .send({ username: 'alice', email: 'alice@test.local' })
    expect(res.status).toBe(400)
  })

  test('rejects login with a tampered session cookie', async () => {
    const app = newTestApp()
    const res = await request(app).get('/dashboard').set('Cookie', 'session=not-a-real-token')
    expect(res.status).toBe(401)
  })
})
