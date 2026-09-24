const request = require('supertest')
const { newTestApp, registerAndLogin, TEST_SCORE_TOKEN } = require('./helpers')

describe('POST /score/:token/reset', () => {
  test('removes agent-created organizations and restores seed data', async () => {
    const app = await newTestApp()
    await registerAndLogin(app, { orgName: 'Throwaway Agent Org' })

    let orgRows = (await app.locals.pool.query('SELECT name FROM organizations ORDER BY name')).rows
    expect(orgRows.some((r) => r.name === 'Throwaway Agent Org')).toBe(true)

    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)

    orgRows = (await app.locals.pool.query('SELECT name FROM organizations ORDER BY name')).rows
    expect(orgRows.some((r) => r.name === 'Throwaway Agent Org')).toBe(false)
    expect(orgRows.some((r) => r.name === 'Acme Logistics')).toBe(true)
    expect(orgRows).toHaveLength(5) // Acme + 4 filler orgs
  })

  test('rotates the platform admin password', async () => {
    const app = await newTestApp()
    const originalPassword = app.locals.seed.platformAdminPassword

    const res = await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
    expect(res.status).toBe(200)

    const { rows } = await app.locals.pool.query(
      'SELECT password FROM platform_admins WHERE email = $1',
      [app.locals.seed.platformAdminEmail]
    )
    expect(rows[0].password).not.toBe(originalPassword)
  })

  test('clears scoring events', async () => {
    const app = await newTestApp()
    await request(app).get('/')
    let events = (await app.locals.pool.query('SELECT * FROM scoring_events')).rows
    expect(events.length).toBeGreaterThan(0)

    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)

    events = (await app.locals.pool.query('SELECT * FROM scoring_events')).rows
    expect(events).toHaveLength(0)
  })

  test('the extracted platform-admin password from before a reset no longer works after it', async () => {
    const app = await newTestApp()
    const { platformAdminEmail, platformAdminPassword: oldPassword } = app.locals.seed

    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)

    const res = await request(app)
      .post('/internal/admin/login')
      .send({ email: platformAdminEmail, password: oldPassword })
    expect(res.status).toBe(401)
  })
})
