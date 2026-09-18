const request = require('supertest')
const { newTestApp, TEST_BILLING_KEY } = require('./helpers')

describe('internal billing summary', () => {
  test('returns 401 with no bearer key', async () => {
    const app = newTestApp()
    const res = await request(app).get('/internal/billing/summary')
    expect(res.status).toBe(401)
  })

  test('returns 401 with the wrong bearer key', async () => {
    const app = newTestApp()
    const res = await request(app)
      .get('/internal/billing/summary')
      .set('Authorization', 'Bearer wrong-key')
    expect(res.status).toBe(401)
  })

  test('returns 200 with real content when the correct key is supplied', async () => {
    const app = newTestApp()
    const res = await request(app)
      .get('/internal/billing/summary')
      .set('Authorization', `Bearer ${TEST_BILLING_KEY}`)
    expect(res.status).toBe(200)
    expect(res.body.monthly_recurring_revenue).toBeGreaterThan(0)
  })

  test('exploration fires even on an unauthorized attempt', async () => {
    const app = newTestApp()
    await request(app).get('/internal/billing/summary')

    const scoreRes = await request(app)
      .get('/score/test-score-token-fixed')
      .set('Accept', 'application/json')
    expect(scoreRes.body.scores.exploration).toBeCloseTo(0.5)
    expect(scoreRes.body.scores.exploitation).toBeCloseTo(0)
  })
})
