const request = require('supertest')
const { newTestApp, registerAndLogin } = require('./helpers')

describe('public and authenticated pages', () => {
  test('GET / renders the landing page', async () => {
    const { app } = await newTestApp()
    const res = await request(app).get('/')
    expect(res.status).toBe(200)
    expect(res.text).toContain('Fernhollow')
  })

  test('GET /login renders the login page', async () => {
    const { app } = await newTestApp()
    const res = await request(app).get('/login')
    expect(res.status).toBe(200)
  })

  test('GET /register renders the registration page', async () => {
    const { app } = await newTestApp()
    const res = await request(app).get('/register')
    expect(res.status).toBe(200)
  })

  test('GET /reset-password renders the reset request page', async () => {
    const { app } = await newTestApp()
    const res = await request(app).get('/reset-password')
    expect(res.status).toBe(200)
  })

  test('GET /reset-password/confirm renders the confirm page', async () => {
    const { app } = await newTestApp()
    const res = await request(app).get('/reset-password/confirm')
    expect(res.status).toBe(200)
  })

  test('GET /dashboard requires authentication', async () => {
    const { app } = await newTestApp()
    const res = await request(app).get('/dashboard')
    expect(res.status).toBe(401)
  })

  test('GET /profile requires authentication', async () => {
    const { app } = await newTestApp()
    const res = await request(app).get('/profile')
    expect(res.status).toBe(401)
  })

  test('GET /directory requires authentication', async () => {
    const { app } = await newTestApp()
    const res = await request(app).get('/directory')
    expect(res.status).toBe(401)
  })

  test('GET /dashboard renders for an authenticated user', async () => {
    const { app } = await newTestApp()
    const cookie = await registerAndLogin(app)
    const res = await request(app).get('/dashboard').set('Cookie', cookie)
    expect(res.status).toBe(200)
    expect(res.text).toContain('alice')
  })

  test('GET /profile renders the caller\'s own account details', async () => {
    const { app } = await newTestApp()
    const cookie = await registerAndLogin(app)
    const res = await request(app).get('/profile').set('Cookie', cookie)
    expect(res.status).toBe(200)
    expect(res.text).toContain('alice@test.local')
  })

  test('an invalid session cookie is rejected', async () => {
    const { app } = await newTestApp()
    const res = await request(app).get('/dashboard').set('Cookie', 'session=not-a-real-jwt')
    expect(res.status).toBe(401)
  })
})
