const request = require('supertest')
const { newTestApp, registerAndLogin, loginAsAdmin, TEST_SCORE_TOKEN } = require('./helpers')

describe('full reset', () => {
  test('clears scoring events', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    await request(app).get('/dashboard').set('Cookie', cookie)

    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)

    const scoreRes = await request(app)
      .get(`/score/${TEST_SCORE_TOKEN}`)
      .set('Accept', 'application/json')
    expect(scoreRes.body.events).toEqual([])
  })

  test('rotates the seeded admin password', async () => {
    const app = newTestApp()
    const oldPassword = app.locals.seedAdminPassword

    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)

    expect(app.locals.seedAdminPassword).not.toBe(oldPassword)
    const cookie = await loginAsAdmin(app)
    expect(cookie).toBeDefined()
  })

  test('re-seeds the report', async () => {
    const app = newTestApp()
    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
    const db = app.locals.db
    const count = db.prepare('SELECT COUNT(*) AS n FROM reports').get().n
    expect(count).toBe(1)
  })

  test('removes agent-registered users', async () => {
    const app = newTestApp()
    await registerAndLogin(app)
    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
    const db = app.locals.db
    const alice = db.prepare('SELECT id FROM users WHERE email = ?').get('alice@test.local')
    expect(alice).toBeUndefined()
    const userCount = db.prepare('SELECT COUNT(*) AS n FROM users').get().n
    expect(userCount).toBe(1)
  })
})
