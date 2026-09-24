const request = require('supertest')
const { newTestApp, registerAndLogin } = require('./helpers')

describe('POST /internal/admin/login', () => {
  test('succeeds for the seeded platform admin', async () => {
    const app = await newTestApp()
    const { platformAdminEmail, platformAdminPassword } = app.locals.seed
    const res = await request(app)
      .post('/internal/admin/login')
      .send({ email: platformAdminEmail, password: platformAdminPassword })
    expect(res.status).toBe(200)
    expect(res.headers['set-cookie'][0]).toMatch(/^admin_session=/)
  })

  test('rejects a wrong password', async () => {
    const app = await newTestApp()
    const { platformAdminEmail } = app.locals.seed
    const res = await request(app)
      .post('/internal/admin/login')
      .send({ email: platformAdminEmail, password: 'definitely-wrong' })
    expect(res.status).toBe(401)
  })

  test('rejects an ordinary member email', async () => {
    const app = await newTestApp()
    const res = await request(app)
      .post('/internal/admin/login')
      .send({ email: 'priya@acmelogistics.example', password: 'whatever' })
    expect(res.status).toBe(401)
  })
})

describe('GET /internal/admin/infra-runbook', () => {
  test('requires a platform-admin session, not just any session', async () => {
    const app = await newTestApp()
    const res = await request(app).get('/internal/admin/infra-runbook')
    expect(res.status).toBe(401)
  })

  test('rejects an ordinary member session, even an org_admin', async () => {
    const app = await newTestApp()
    const { cookie } = await registerAndLogin(app)
    const res = await request(app).get('/internal/admin/infra-runbook').set('Cookie', cookie)
    expect(res.status).toBe(401)
  })

  test('succeeds for an authenticated platform-admin session', async () => {
    const app = await newTestApp()
    const { platformAdminEmail, platformAdminPassword } = app.locals.seed
    const loginRes = await request(app)
      .post('/internal/admin/login')
      .send({ email: platformAdminEmail, password: platformAdminPassword })
    const adminCookie = loginRes.headers['set-cookie'][0].split(';')[0]

    const res = await request(app)
      .get('/internal/admin/infra-runbook')
      .set('Cookie', adminCookie)
    expect(res.status).toBe(200)
    expect(res.text).toContain('Infrastructure Runbook')
  })
})
