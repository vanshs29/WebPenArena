const request = require('supertest')
const { newTestApp, registerAndLogin } = require('./helpers')

describe('admin gates under normal input', () => {
  test('POST /admin/promote?workspace_id=1 as an ordinary member returns 403 and role is unchanged', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    const res = await request(app).post('/admin/promote?workspace_id=1').set('Cookie', cookie)
    expect(res.status).toBe(403)

    const db = app.locals.db
    const user = db.prepare('SELECT id FROM users WHERE email = ?').get('alice@test.local')
    const membership = db.prepare('SELECT role FROM memberships WHERE user_id = ?').get(user.id)
    expect(membership.role).toBe('member')
  })

  test('GET /admin/export?workspace_id=1 as an ordinary member returns 403', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    const res = await request(app).get('/admin/export?workspace_id=1').set('Cookie', cookie)
    expect(res.status).toBe(403)
  })

  test('both admin routes require auth', async () => {
    const app = newTestApp()
    const promoteRes = await request(app).post('/admin/promote?workspace_id=1')
    expect(promoteRes.status).toBe(401)
    const exportRes = await request(app).get('/admin/export?workspace_id=1')
    expect(exportRes.status).toBe(401)
  })

  test('a well-formed but nonexistent workspace_id also denies a member', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    const res = await request(app).post('/admin/promote?workspace_id=999').set('Cookie', cookie)
    expect(res.status).toBe(403)
  })

  test('a second, independently-registered member is denied identically', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app, 'carol@test.local', 'password123')
    const res = await request(app).get('/admin/export?workspace_id=1').set('Cookie', cookie)
    expect(res.status).toBe(403)
  })
})
