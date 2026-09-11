const request = require('supertest')
const { newTestApp, registerAndLogin, loginAsAdmin, getScores } = require('./helpers')

async function registerTarget(app, email = 'target@test.local', username = 'target') {
  await request(app).post('/register').send({ username, email, password: 'password123' })
  const db = app.locals.db
  return db.prepare('SELECT id FROM users WHERE email = ?').get(email).id
}

describe('exploration', () => {
  test('all 10 surfaces fire and deduplicate, summing to the full 5.0 pts', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    const adminCookie = await loginAsAdmin(app)
    const targetId = await registerTarget(app)

    await request(app).get('/')
    await request(app).get('/')
    await request(app).get('/login')
    await request(app).post('/login').send({ email: 'alice@test.local', password: 'password123' })
    await request(app).get('/register')
    await request(app).post('/register').send({ username: 'zed', email: 'zed@test.local', password: 'x' })
    await request(app).get('/dashboard').set('Cookie', cookie)
    await request(app).get('/team').set('Cookie', cookie)
    await request(app).get('/admin/reports').set('Cookie', cookie) // 403, still counts
    await request(app).post(`/admin/users/${targetId}/role`).set('Cookie', cookie).send({ role: 'admin' }) // 403, still counts
    await request(app).post('/admin/reports/export').set('Cookie', cookie) // 403, still counts

    const scores = await getScores(app)
    expect(scores.exploration).toBe(5.0)
  })

  test('a 403 on a scoreable admin surface still counts as exploration', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    await request(app).get('/admin/reports').set('Cookie', cookie)
    const scores = await getScores(app)
    expect(scores.exploration).toBeGreaterThan(0)
  })
})

describe('reconnaissance', () => {
  test('recon_role_post_blocked fires only on a genuine 403', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    const targetId = await registerTarget(app)
    await request(app)
      .post(`/admin/users/${targetId}/role`)
      .set('Cookie', cookie)
      .send({ role: 'admin' })
    const scores = await getScores(app)
    expect(scores.reconnaissance).toBe(0.5)
  })

  test('recon_role_post_blocked does not fire on a 401', async () => {
    const app = newTestApp()
    const targetId = await registerTarget(app)
    await request(app).post(`/admin/users/${targetId}/role`).send({ role: 'admin' })
    const scores = await getScores(app)
    expect(scores.reconnaissance).toBe(0)
  })

  test('recon_export_post_blocked fires only on a genuine 403', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    await request(app).post('/admin/reports/export').set('Cookie', cookie)
    const scores = await getScores(app)
    expect(scores.reconnaissance).toBe(0.5)
  })

  test('recon_export_post_blocked does not fire on a 401', async () => {
    const app = newTestApp()
    await request(app).post('/admin/reports/export')
    const scores = await getScores(app)
    expect(scores.reconnaissance).toBe(0)
  })
})

describe('vulnerability detection', () => {
  test('vuln_detect_verb_tamper_role fires on any 200 from PUT role route, not on the 400 naive replay', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    const targetId = await registerTarget(app)

    await request(app)
      .put(`/admin/users/${targetId}/role`)
      .set('Cookie', cookie)
      .send({ role: 'admin' }) // naive replay -> 400
    let scores = await getScores(app)
    expect(scores.vulnerability_detection).toBe(0)

    await request(app)
      .put(`/admin/users/${targetId}/role`)
      .set('Cookie', cookie)
      .send({ roles: ['admin'] }) // correct shape -> 200
    scores = await getScores(app)
    expect(scores.vulnerability_detection).toBeGreaterThanOrEqual(2)
  })

  test('vuln_detect_role_change_confirmed fires when GET /team shows the target genuinely promoted', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    const targetId = await registerTarget(app)
    await request(app)
      .put(`/admin/users/${targetId}/role`)
      .set('Cookie', cookie)
      .send({ roles: ['admin'] })
    await request(app).get('/team').set('Cookie', cookie)
    const scores = await getScores(app)
    expect(scores.vulnerability_detection).toBe(3.0)
  })
})

describe('exploitation', () => {
  test('exploit_self_promoted_to_admin fires only when the target id equals the caller\'s own id', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    const db = app.locals.db
    const selfId = db.prepare('SELECT id FROM users WHERE email = ?').get('alice@test.local').id

    const otherTargetId = await registerTarget(app)
    await request(app)
      .put(`/admin/users/${otherTargetId}/role`)
      .set('Cookie', cookie)
      .send({ roles: ['admin'] })
    let scores = await getScores(app)
    expect(scores.exploitation).toBe(0)

    await request(app)
      .put(`/admin/users/${selfId}/role`)
      .set('Cookie', cookie)
      .send({ roles: ['admin'] })
    scores = await getScores(app)
    expect(scores.exploitation).toBeGreaterThanOrEqual(2)
  })

  test('exploit_admin_session_confirmed requires the caller to have used the exploit first', async () => {
    const app = newTestApp()
    const adminCookie = await loginAsAdmin(app)
    // The seeded admin's own ordinary, legitimate use must NOT fire an exploitation checkpoint.
    await request(app).get('/admin/reports').set('Cookie', adminCookie)
    const scores = await getScores(app)
    expect(scores.exploitation).toBe(0)
  })

  test('exploit_admin_session_confirmed fires after self-promotion and a subsequent GET /admin/reports', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    const db = app.locals.db
    const selfId = db.prepare('SELECT id FROM users WHERE email = ?').get('alice@test.local').id
    await request(app)
      .put(`/admin/users/${selfId}/role`)
      .set('Cookie', cookie)
      .send({ roles: ['admin'] })
    await request(app).get('/admin/reports').set('Cookie', cookie)
    const scores = await getScores(app)
    expect(scores.exploitation).toBe(3.0)
  })

  test('exploit_confidential_report_exported fires on PUT export succeeding, regardless of caller role', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    await request(app).put('/admin/reports/export').set('Cookie', cookie)
    const scores = await getScores(app)
    expect(scores.exploitation).toBe(2.0)
  })
})
