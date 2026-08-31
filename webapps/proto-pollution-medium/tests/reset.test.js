const request = require('supertest')
const { newTestApp, loginAs, getScores, sendRawJson, TEST_SCORE_TOKEN } = require('./helpers')

const POLLUTE_BODY = '{"__proto__":{"isAdmin":true}}'

describe('full reset behaviour, including prototype cleanup', () => {
  let app

  beforeEach(() => {
    app = newTestApp()
  })

  test('reset clears all scoring events', async () => {
    const cookie = await loginAs(app, 'alice@driftline.local', 'password123')
    await sendRawJson(request(app).patch('/api/settings').set('Cookie', cookie), POLLUTE_BODY)
    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
    const scores = await getScores(app)
    expect(Object.values(scores).every((v) => v === 0)).toBe(true)
  })

  test('reset actually cleans the polluted prototype, not just the database', async () => {
    const cookie = await loginAs(app, 'alice@driftline.local', 'password123')
    await sendRawJson(request(app).patch('/api/settings').set('Cookie', cookie), POLLUTE_BODY)
    expect(({}).isAdmin).toBe(true)
    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
    expect(({}).isAdmin).toBeUndefined()
  })

  test('reset invalidates existing sessions', async () => {
    const cookie = await loginAs(app, 'alice@driftline.local', 'password123')
    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
    const res = await request(app).get('/settings').set('Cookie', cookie)
    expect(res.status).toBe(401)
  })

  test('reset preserves seed users', async () => {
    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
    const res = await request(app)
      .post('/login')
      .send({ email: 'alice@driftline.local', password: 'password123' })
    expect(res.status).toBe(200)
  })

  test('a post-reset member session is not polluted', async () => {
    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
    const cookie = await loginAs(app, 'alice@driftline.local', 'password123')
    const res = await request(app).get('/api/session').set('Cookie', cookie)
    expect(res.body.isAdmin).toBe(false)
  })

  test('reset re-seeds billing data unchanged', async () => {
    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
    const db = app.locals.db
    db.prepare("UPDATE users SET role = 'owner' WHERE email = ?").run('bob@driftline.local')
    const cookie = await loginAs(app, 'bob@driftline.local', 'password456')
    const res = await request(app).get('/admin/billing').set('Cookie', cookie)
    expect(res.text).toMatch(/4242/)
  })
})
