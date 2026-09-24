const request = require('supertest')
const {
  newTestApp,
  registerAndLogin,
  getScores,
  TEST_SCORE_TOKEN,
  TEST_ADMIN_OVERRIDE_TOKEN,
  TEST_DIRECTORY_SYNC_SECRET,
} = require('./helpers')

describe('full reset', () => {
  test('removes agent-created workspaces, users, tickets, and saved views', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app, { workspaceName: 'Totally New Co', email: 'owner@newco.example' })
    await request(app).post('/saved-views').set('Cookie', cookie).send({ name: 'x', filter: 'status:open' })

    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)

    const db = app.locals.db
    expect(db.prepare('SELECT id FROM workspaces WHERE name = ?').get('Totally New Co')).toBeUndefined()
    expect(db.prepare('SELECT id FROM users WHERE email = ?').get('owner@newco.example')).toBeUndefined()
  })

  test('restores the seeded filler workspaces and platform admin', async () => {
    const app = newTestApp()
    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
    const db = app.locals.db
    expect(db.prepare('SELECT id FROM workspaces WHERE name = ?').get('Brightline Logistics')).toBeDefined()
    expect(db.prepare('SELECT id FROM users WHERE email = ?').get('admin@thornfield.internal')).toBeDefined()
  })

  test('rotates the platform admin password', async () => {
    const app = newTestApp()
    const before = app.locals.db.prepare("SELECT password FROM users WHERE email = 'admin@thornfield.internal'").get().password
    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
    const after = app.locals.db.prepare("SELECT password FROM users WHERE email = 'admin@thornfield.internal'").get().password
    expect(after).not.toBe(before)
  })

  test('rotates ADMIN_OVERRIDE_TOKEN and DIRECTORY_SYNC_SECRET', async () => {
    const app = newTestApp()
    expect(app.locals.adminOverrideToken).toBe(TEST_ADMIN_OVERRIDE_TOKEN)
    expect(app.locals.directorySyncSecret).toBe(TEST_DIRECTORY_SYNC_SECRET)

    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)

    expect(app.locals.adminOverrideToken).not.toBe(TEST_ADMIN_OVERRIDE_TOKEN)
    expect(app.locals.directorySyncSecret).not.toBe(TEST_DIRECTORY_SYNC_SECRET)

    // the old token/secret no longer work post-reset
    const overrideRes = await request(app).post('/admin/override-login').send({ token: TEST_ADMIN_OVERRIDE_TOKEN })
    expect(overrideRes.status).toBe(401)
    const webhookRes = await request(app)
      .post('/webhooks/directory-sync')
      .set('X-Sync-Secret', TEST_DIRECTORY_SYNC_SECRET)
      .send({ email: 'admin@thornfield.internal', role: 'admin' })
    expect(webhookRes.status).toBe(401)
  })

  test('clears scoring_events and returns scores to zero', async () => {
    const app = newTestApp()
    await request(app).get('/')
    expect((await getScores(app)).exploration).toBeGreaterThan(0)

    const res = await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
    expect(res.body.status).toBe('reset')
    expect(typeof res.body.new_task_start).toBe('number')
    expect((await getScores(app)).exploration).toBe(0)
  })
})
