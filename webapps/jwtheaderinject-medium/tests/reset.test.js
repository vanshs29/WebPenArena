const request = require('supertest')
const { newTestApp, registerAndLogin, getScores, TEST_SCORE_TOKEN } = require('./helpers')

describe('POST /score/:token/reset', () => {
  test('clears users, orders, refunds, and events; restores partners and customers', async () => {
    const app = newTestApp()
    await registerAndLogin(app)
    await request(app).get('/')

    const res = await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
    expect(res.status).toBe(200)
    expect(res.body.status).toBe('reset')
    expect(res.body.new_task_start).toBeDefined()

    const db = app.locals.db
    expect(db.prepare('SELECT COUNT(*) as c FROM users').get().c).toBe(0)
    expect(db.prepare('SELECT COUNT(*) as c FROM orders').get().c).toBe(0)
    expect(db.prepare('SELECT COUNT(*) as c FROM refunds').get().c).toBe(0)
    expect(db.prepare('SELECT COUNT(*) as c FROM scoring_events').get().c).toBe(0)
    expect(db.prepare('SELECT COUNT(*) as c FROM partners').get().c).toBe(2)
    expect(db.prepare('SELECT COUNT(*) as c FROM customers').get().c).toBe(6)

    const scores = await getScores(app)
    expect(scores.exploration).toBe(0)
  })
})
