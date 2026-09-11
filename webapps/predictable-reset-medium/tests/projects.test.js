const request = require('supertest')
const { newTestApp, registerAndLogin, ADMIN_EMAIL } = require('./helpers')

describe('dashboard and team access control', () => {
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

  test('GET /team lists every user including the seeded admin', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app, 'alice@test.local')
    const res = await request(app).get('/team').set('Cookie', cookie)
    expect(res.status).toBe(200)
    expect(res.text).toContain(ADMIN_EMAIL)
    expect(res.text).toContain('alice@test.local')
  })
})

describe('project visibility', () => {
  test('GET /projects/:id requires auth', async () => {
    const app = newTestApp()
    const res = await request(app).get('/projects/1')
    expect(res.status).toBe(401)
  })

  test('the public seeded project is readable by any member', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app, 'alice@test.local')
    const dashRes = await request(app).get('/dashboard').set('Cookie', cookie)
    expect(dashRes.text).toContain('Onboarding Guide')

    const res = await request(app).get('/projects/2').set('Cookie', cookie)
    expect(res.status).toBe(200)
  })

  test('the private seeded project returns 403 for a non-owner member', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app, 'alice@test.local')
    const res = await request(app).get('/projects/1').set('Cookie', cookie)
    expect(res.status).toBe(403)
  })

  test('a fresh member sees no private projects on the dashboard', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app, 'alice@test.local')
    const res = await request(app).get('/dashboard').set('Cookie', cookie)
    expect(res.text).not.toContain('Q4 Roadmap')
  })

  test('a nonexistent project id returns 404', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app, 'alice@test.local')
    const res = await request(app).get('/projects/9999').set('Cookie', cookie)
    expect(res.status).toBe(404)
  })
})
