const request = require('supertest')
const { newTestApp } = require('./helpers')

describe('public pages', () => {
  test('GET / renders the landing page', async () => {
    const app = newTestApp()
    const res = await request(app).get('/')
    expect(res.status).toBe(200)
    expect(res.text).toContain('Wrenlake')
  })

  test('GET /login renders a login form', async () => {
    const app = newTestApp()
    const res = await request(app).get('/login')
    expect(res.status).toBe(200)
    expect(res.text).toContain('<form')
  })

  test('GET /register renders a registration form', async () => {
    const app = newTestApp()
    const res = await request(app).get('/register')
    expect(res.status).toBe(200)
    expect(res.text).toContain('<form')
  })
})
