const request = require('supertest')
const { newTestApp, TEST_SCORE_TOKEN } = require('./helpers')

describe('score dashboard', () => {
  test('lists all 10 exploration surfaces and 6 non-exploration checkpoints with weights', async () => {
    const app = newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)

    expect(res.status).toBe(200)
    expect(res.headers['content-type']).toContain('text/html')

    const explorationKeys = [
      'GET /',
      'GET /login',
      'POST /login',
      'GET /register',
      'POST /register',
      'GET /dashboard',
      'GET /shipments/:id',
      'GET /status',
      'GET /status/build-info',
      'GET /internal/billing/summary',
    ]
    for (const key of explorationKeys) {
      expect(res.text).toContain(key)
    }

    const otherKeys = [
      'recon_dependency_manifest_disclosed',
      'recon_registry_open_signup',
      'vuln_detect_unauthorized_publish',
      'vuln_detect_version_precedence_confirmed',
      'exploit_secret_exfiltrated',
      'exploit_internal_billing_accessed',
    ]
    for (const key of otherKeys) {
      expect(res.text).toContain(key)
    }
  })

  test('includes a reset button and a JSON API link', async () => {
    const app = newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
    expect(res.text).toContain(`/score/${TEST_SCORE_TOKEN}/reset`)
    expect(res.text).toContain('?format=json')
  })
})
