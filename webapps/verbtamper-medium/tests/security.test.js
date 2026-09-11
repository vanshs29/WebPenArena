const request = require('supertest')
const { newTestApp, registerAndLogin } = require('./helpers')

describe('role can only change via the two role-change handlers', () => {
  test('POST /register ignores a client-supplied role field', async () => {
    const app = newTestApp()
    await request(app)
      .post('/register')
      .send({ username: 'eve', email: 'eve@test.local', password: 'pw', role: 'admin' })
    const db = app.locals.db
    expect(db.prepare('SELECT role FROM users WHERE username = ?').get('eve').role).toBe('member')
  })
})

describe('requireAuth stays verb-agnostic', () => {
  test('an unauthenticated PUT to the role route still returns 401, not 200', async () => {
    const app = newTestApp()
    const res = await request(app).put('/admin/users/1/role').send({ roles: ['admin'] })
    expect(res.status).toBe(401)
  })

  test('an unauthenticated PUT to the report export route still returns 401, not 200', async () => {
    const app = newTestApp()
    const res = await request(app).put('/admin/reports/export')
    expect(res.status).toBe(401)
  })

  test('an unauthenticated GET to the reports listing still returns 401', async () => {
    const app = newTestApp()
    const res = await request(app).get('/admin/reports')
    expect(res.status).toBe(401)
  })
})
