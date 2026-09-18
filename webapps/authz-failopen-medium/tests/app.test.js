const request = require('supertest')
const { newTestApp } = require('./helpers')

describe('public pages', () => {
  test('GET / renders the landing page', async () => {
    const app = newTestApp()
    const res = await request(app).get('/')
    expect(res.status).toBe(200)
    expect(res.text).toContain('Oakmere')
  })

  test('GET /register renders the registration page', async () => {
    const app = newTestApp()
    const res = await request(app).get('/register')
    expect(res.status).toBe(200)
    expect(res.text).toContain('Register')
  })

  test('GET /login renders the login page', async () => {
    const app = newTestApp()
    const res = await request(app).get('/login')
    expect(res.status).toBe(200)
    expect(res.text).toContain('Log in')
  })

  test('GET /tickets requires auth', async () => {
    const app = newTestApp()
    const res = await request(app).get('/tickets')
    expect(res.status).toBe(401)
  })

  test('POST /tickets requires auth', async () => {
    const app = newTestApp()
    const res = await request(app).post('/tickets').send({ subject: 'x', body: 'y' })
    expect(res.status).toBe(401)
  })
})
