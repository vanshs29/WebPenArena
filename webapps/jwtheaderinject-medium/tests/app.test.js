const request = require('supertest')
const { newTestApp } = require('./helpers')

describe('public pages', () => {
  test('GET / renders the landing page', async () => {
    const app = newTestApp()
    const res = await request(app).get('/')
    expect(res.status).toBe(200)
    expect(res.text).toContain('Larkmoor')
  })

  test('GET /login renders without auth', async () => {
    const app = newTestApp()
    const res = await request(app).get('/login')
    expect(res.status).toBe(200)
  })

  test('GET /register renders without auth', async () => {
    const app = newTestApp()
    const res = await request(app).get('/register')
    expect(res.status).toBe(200)
  })

  test('GET /docs/partner-api renders without auth', async () => {
    const app = newTestApp()
    const res = await request(app).get('/docs/partner-api')
    expect(res.status).toBe(200)
    expect(res.text).toContain('x5c')
  })

  test('GET /partners renders without auth and lists both seeded partners', async () => {
    const app = newTestApp()
    const res = await request(app).get('/partners')
    expect(res.status).toBe(200)
    expect(res.text).toContain('default-tier')
    expect(res.text).toContain('acme-enterprise')
  })
})
