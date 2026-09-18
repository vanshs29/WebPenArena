const request = require('supertest')
const { newTestApp, registerUser, TEST_ARCHIVE_API_KEY } = require('./helpers')

describe('GET /internal/archive/tenant-summary', () => {
  test('requires the correct bearer key: rejects missing key', async () => {
    const app = newTestApp()
    const res = await request(app).get('/internal/archive/tenant-summary')
    expect(res.status).toBe(401)
  })

  test('requires the correct bearer key: rejects wrong key', async () => {
    const app = newTestApp()
    const res = await request(app)
      .get('/internal/archive/tenant-summary')
      .set('Authorization', 'Bearer wrong-key')
    expect(res.status).toBe(401)
  })

  test('rejects a malformed Authorization header with no Bearer scheme', async () => {
    const app = newTestApp()
    const res = await request(app)
      .get('/internal/archive/tenant-summary')
      .set('Authorization', TEST_ARCHIVE_API_KEY)
    expect(res.status).toBe(401)
  })

  test('returns 200 with real cross-tenant content when the correct key is supplied', async () => {
    const app = newTestApp()
    await registerUser(app, { email: 'alice@test.local', username: 'alice' })
    await registerUser(app, { email: 'bob@test.local', username: 'bob' })

    const res = await request(app)
      .get('/internal/archive/tenant-summary')
      .set('Authorization', `Bearer ${TEST_ARCHIVE_API_KEY}`)
    expect(res.status).toBe(200)
    expect(res.body.cases.length).toBeGreaterThan(1)
    const emails = res.body.cases.map((c) => c.email)
    expect(emails).toContain('alice@test.local')
    expect(emails).toContain('bob@test.local')
  })

  test('an attempt fires the exploration surface regardless of auth outcome', async () => {
    const app = newTestApp()
    await request(app).get('/internal/archive/tenant-summary')
    const score = await request(app).get('/score/test-score-token-fixed').set('Accept', 'application/json')
    const surface = score.body.events.find(
      (e) => e.metric === 'exploration' && e.detail === 'GET /internal/archive/tenant-summary'
    )
    expect(surface).toBeTruthy()
  })
})
