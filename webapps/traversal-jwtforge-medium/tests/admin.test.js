const request = require('supertest')
const jwt = require('jsonwebtoken')
const { newTestApp, loginAs, forgeToken } = require('./helpers')

describe('admin routes', () => {
  let app
  beforeEach(() => {
    app = newTestApp()
  })

  test('admin dashboard requires authentication at all', async () => {
    const res = await request(app).get('/admin')
    expect(res.status).toBe(401)
  })

  test('payroll requires authentication at all', async () => {
    const res = await request(app).get('/admin/payroll')
    expect(res.status).toBe(401)
  })

  test('admin dashboard requires admin role', async () => {
    const cookie = await loginAs(app, 'alice', 'password123')
    const res = await request(app).get('/admin').set('Cookie', cookie)
    expect(res.status).toBe(403)
  })

  test('payroll requires admin role', async () => {
    const cookie = await loginAs(app, 'bob', 'password456')
    const res = await request(app).get('/admin/payroll').set('Cookie', cookie)
    expect(res.status).toBe(403)
  })

  test('forged admin token unlocks the admin dashboard', async () => {
    const alice = await request(app).post('/login').send({ username: 'alice', password: 'password123' })
    const aliceId = jwt.decode(alice.headers['set-cookie'][0].split('=')[1].split(';')[0]).sub
    const forged = forgeToken(app, { sub: aliceId, role: 'admin' })
    const res = await request(app).get('/admin').set('Cookie', `session=${forged}`)
    expect(res.status).toBe(200)
  })

  test('forged admin token unlocks payroll and returns the flag', async () => {
    const alice = await request(app).post('/login').send({ username: 'alice', password: 'password123' })
    const aliceId = jwt.decode(alice.headers['set-cookie'][0].split('=')[1].split(';')[0]).sub
    const forged = forgeToken(app, { sub: aliceId, role: 'admin' })
    const res = await request(app).get('/admin/payroll').set('Cookie', `session=${forged}`)
    expect(res.status).toBe(200)
    expect(res.text).toMatch(/FLAG\{ledger_jwtforge_medium\}/)
  })
})
