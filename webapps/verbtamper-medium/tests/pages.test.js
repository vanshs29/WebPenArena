const request = require('supertest')
const { newTestApp, registerAndLogin } = require('./helpers')

describe('dashboard and team roster', () => {
  test('GET /dashboard requires auth', async () => {
    const app = newTestApp()
    const res = await request(app).get('/dashboard')
    expect(res.status).toBe(401)
  })

  test('GET /team requires auth', async () => {
    const app = newTestApp()
    const res = await request(app).get('/team')
    expect(res.status).toBe(401)
  })

  test('GET /dashboard succeeds for an authenticated member', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    const res = await request(app).get('/dashboard').set('Cookie', cookie)
    expect(res.status).toBe(200)
  })

  test('GET /team lists every user, including the seeded admin and its role', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    const res = await request(app).get('/team').set('Cookie', cookie)
    expect(res.status).toBe(200)
    expect(res.text).toContain('ops-admin')
    expect(res.text).toContain('admin')
    expect(res.text).toContain('alice')
  })
})
