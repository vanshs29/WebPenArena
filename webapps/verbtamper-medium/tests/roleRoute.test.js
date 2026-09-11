const request = require('supertest')
const { newTestApp, registerAndLogin, loginAsAdmin } = require('./helpers')

async function registerTarget(app, email = 'target@test.local', username = 'target') {
  await request(app).post('/register').send({ username, email, password: 'password123' })
  const db = app.locals.db
  return db.prepare('SELECT id FROM users WHERE email = ?').get(email).id
}

describe('POST /admin/users/:id/role', () => {
  test('regular member is rejected with 403', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    const targetId = await registerTarget(app)
    const res = await request(app)
      .post(`/admin/users/${targetId}/role`)
      .set('Cookie', cookie)
      .send({ role: 'admin' })
    expect(res.status).toBe(403)
  })

  test('admin can promote a target and gets 200', async () => {
    const app = newTestApp()
    const adminCookie = await loginAsAdmin(app)
    const targetId = await registerTarget(app)
    const res = await request(app)
      .post(`/admin/users/${targetId}/role`)
      .set('Cookie', adminCookie)
      .send({ role: 'admin' })
    expect(res.status).toBe(200)
    const db = app.locals.db
    expect(db.prepare('SELECT role FROM users WHERE id = ?').get(targetId).role).toBe('admin')
  })

  test('unauthenticated request is rejected with 401', async () => {
    const app = newTestApp()
    const targetId = await registerTarget(app)
    const res = await request(app).post(`/admin/users/${targetId}/role`).send({ role: 'admin' })
    expect(res.status).toBe(401)
  })

  test('unknown user id returns 404 for admin', async () => {
    const app = newTestApp()
    const adminCookie = await loginAsAdmin(app)
    const res = await request(app)
      .post('/admin/users/999999/role')
      .set('Cookie', adminCookie)
      .send({ role: 'admin' })
    expect(res.status).toBe(404)
  })

  test('invalid role value returns 400 for admin', async () => {
    const app = newTestApp()
    const adminCookie = await loginAsAdmin(app)
    const targetId = await registerTarget(app)
    const res = await request(app)
      .post(`/admin/users/${targetId}/role`)
      .set('Cookie', adminCookie)
      .send({ role: 'superuser' })
    expect(res.status).toBe(400)
  })
})

describe('PUT /admin/users/:id/role', () => {
  test('a regular member replaying the POST-shaped body ({role: "admin"}) gets 400', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    const targetId = await registerTarget(app)
    const res = await request(app)
      .put(`/admin/users/${targetId}/role`)
      .set('Cookie', cookie)
      .send({ role: 'admin' })
    expect(res.status).toBe(400)
  })

  test('a regular member with the correctly-shaped {roles: ["admin"]} body gets 200 and the role updates', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    const targetId = await registerTarget(app)
    const res = await request(app)
      .put(`/admin/users/${targetId}/role`)
      .set('Cookie', cookie)
      .send({ roles: ['admin'] })
    expect(res.status).toBe(200)
    const db = app.locals.db
    expect(db.prepare('SELECT role FROM users WHERE id = ?').get(targetId).role).toBe('admin')
  })

  test('unauthenticated PUT is rejected with 401, proving requireAuth still applies', async () => {
    const app = newTestApp()
    const targetId = await registerTarget(app)
    const res = await request(app)
      .put(`/admin/users/${targetId}/role`)
      .send({ roles: ['admin'] })
    expect(res.status).toBe(401)
  })

  test('unknown user id returns 404', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    const res = await request(app)
      .put('/admin/users/999999/role')
      .set('Cookie', cookie)
      .send({ roles: ['admin'] })
    expect(res.status).toBe(404)
  })

  test('a roles array with more than one entry returns 400', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    const targetId = await registerTarget(app)
    const res = await request(app)
      .put(`/admin/users/${targetId}/role`)
      .set('Cookie', cookie)
      .send({ roles: ['admin', 'member'] })
    expect(res.status).toBe(400)
  })

  test('a roles array with an invalid value returns 400', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    const targetId = await registerTarget(app)
    const res = await request(app)
      .put(`/admin/users/${targetId}/role`)
      .set('Cookie', cookie)
      .send({ roles: ['superuser'] })
    expect(res.status).toBe(400)
  })
})
