const request = require('supertest')
const { newTestApp } = require('./helpers')

describe('public routes', () => {
  test('GET / renders the landing page', async () => {
    const app = newTestApp()
    const res = await request(app).get('/')
    expect(res.status).toBe(200)
    expect(res.text).toContain('Ashwell')
  })

  test('GET /login renders the login page', async () => {
    const app = newTestApp()
    const res = await request(app).get('/login')
    expect(res.status).toBe(200)
    expect(res.text).toContain('Log in')
  })

  test('GET /register renders the registration page', async () => {
    const app = newTestApp()
    const res = await request(app).get('/register')
    expect(res.status).toBe(200)
    expect(res.text).toContain('Register')
  })

  test('GET /dashboard requires auth', async () => {
    const app = newTestApp()
    const res = await request(app).get('/dashboard')
    expect(res.status).toBe(401)
  })

  test('GET /case/:id requires auth', async () => {
    const app = newTestApp()
    const res = await request(app).get('/case/1')
    expect(res.status).toBe(401)
  })
})
