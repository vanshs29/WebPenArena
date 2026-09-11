const request = require('supertest')
const { newTestApp } = require('./helpers')

describe('public pages', () => {
  test('GET / renders the landing page', async () => {
    const app = newTestApp()
    const res = await request(app).get('/')
    expect(res.status).toBe(200)
    expect(res.text).toContain('Foundry')
  })

  test('GET /login renders the login form', async () => {
    const app = newTestApp()
    const res = await request(app).get('/login')
    expect(res.status).toBe(200)
    expect(res.text).toContain('Log in')
  })

  test('GET /register renders the registration form', async () => {
    const app = newTestApp()
    const res = await request(app).get('/register')
    expect(res.status).toBe(200)
    expect(res.text).toContain('Register')
  })

  test('GET /forgot-password renders the request-a-reset form', async () => {
    const app = newTestApp()
    const res = await request(app).get('/forgot-password')
    expect(res.status).toBe(200)
    expect(res.text).toContain('Forgot password')
  })

  test('GET /reset-password renders the confirm form', async () => {
    const app = newTestApp()
    const res = await request(app).get('/reset-password')
    expect(res.status).toBe(200)
    expect(res.text).toContain('Reset password')
  })
})
