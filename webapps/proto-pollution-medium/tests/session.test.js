const request = require('supertest')
const { newTestApp, loginAs, sendRawJson } = require('./helpers')

describe('/api/session reflects isAdmin honestly', () => {
  let app

  beforeEach(() => {
    app = newTestApp()
  })

  test('a normal member session reports isAdmin false', async () => {
    const cookie = await loginAs(app, 'alice@driftline.local', 'password123')
    const res = await request(app).get('/api/session').set('Cookie', cookie)
    expect(res.body).toEqual({ email: 'alice@driftline.local', role: 'member', isAdmin: false })
  })

  test('the real owner reports isAdmin false too (their access comes from role, not this flag)', async () => {
    const db = app.locals.db
    db.prepare("UPDATE users SET role = 'owner' WHERE email = ?").run('bob@driftline.local')
    const cookie = await loginAs(app, 'bob@driftline.local', 'password456')
    const res = await request(app).get('/api/session').set('Cookie', cookie)
    expect(res.body).toEqual({ email: 'bob@driftline.local', role: 'owner', isAdmin: false })
  })

  test('session endpoint requires auth', async () => {
    const res = await request(app).get('/api/session')
    expect(res.status).toBe(401)
  })

  test('reports isAdmin true once polluted', async () => {
    const cookie = await loginAs(app, 'alice@driftline.local', 'password123')
    await sendRawJson(
      request(app).patch('/api/settings').set('Cookie', cookie),
      '{"__proto__":{"isAdmin":true}}'
    )
    const res = await request(app).get('/api/session').set('Cookie', cookie)
    expect(res.body.isAdmin).toBe(true)
  })
})
