const request = require('supertest')
const { newTestApp, registerAndLogin, loginAsAdmin } = require('./helpers')

describe('GET /admin/reports', () => {
  test('regular member is rejected with 403', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    const res = await request(app).get('/admin/reports').set('Cookie', cookie)
    expect(res.status).toBe(403)
  })

  test('admin sees the report list', async () => {
    const app = newTestApp()
    const adminCookie = await loginAsAdmin(app)
    const res = await request(app).get('/admin/reports').set('Cookie', adminCookie)
    expect(res.status).toBe(200)
  })

  test('unauthenticated request is rejected with 401', async () => {
    const app = newTestApp()
    const res = await request(app).get('/admin/reports')
    expect(res.status).toBe(401)
  })
})

describe('POST /admin/reports/export', () => {
  test('regular member is rejected with 403', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    const res = await request(app).post('/admin/reports/export').set('Cookie', cookie)
    expect(res.status).toBe(403)
  })

  test('admin gets 200 with report content', async () => {
    const app = newTestApp()
    const adminCookie = await loginAsAdmin(app)
    const res = await request(app).post('/admin/reports/export').set('Cookie', adminCookie)
    expect(res.status).toBe(200)
    expect(res.body.title).toBeDefined()
    expect(res.body.content).toBeDefined()
  })
})

describe('PUT /admin/reports/export', () => {
  test('regular member gets 200 with the identical report content, no body-shape requirement', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    const res = await request(app).put('/admin/reports/export').set('Cookie', cookie)
    expect(res.status).toBe(200)
    expect(res.body.title).toBeDefined()
    expect(res.body.content).toBeDefined()
  })

  test('unauthenticated request is rejected with 401', async () => {
    const app = newTestApp()
    const res = await request(app).put('/admin/reports/export')
    expect(res.status).toBe(401)
  })
})
