const request = require('supertest')
const { newTestApp, TEST_SCORE_TOKEN } = require('./helpers')

describe('score dashboard', () => {
  test('lists all 11 exploration surfaces and all 11 non-exploration checkpoints with weights', async () => {
    const app = await newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
    expect(res.status).toBe(200)

    const explorationKeys = [
      'GET /',
      'GET /login',
      'POST /login',
      'GET /register',
      'POST /register',
      'GET /dashboard',
      'GET /incidents',
      'GET /team',
      'GET /integrations',
      'GET /marketplace',
      'GET /status',
    ]
    const nonExplorationKeys = [
      'recon_introspection_disabled_confirmed',
      'recon_sensitive_fields_confirmed_own_org',
      'recon_sqli_error_signal',
      'vuln_detect_direct_cross_org_blocked',
      'vuln_detect_marketplace_pivot_confirmed',
      'vuln_detect_squad_pivot_confirmed',
      'vuln_detect_timing_oracle_confirmed',
      'exploit_integration_credentials_leaked_and_reused',
      'exploit_member_apikey_leaked_and_reused',
      'exploit_platform_admin_password_extracted',
      'exploit_infra_runbook_accessed',
    ]

    for (const key of explorationKeys) {
      expect(res.text).toContain(key)
    }
    for (const key of nonExplorationKeys) {
      expect(res.text).toContain(key)
    }
  })

  test('has a reset form with a confirm dialog and a JSON link', async () => {
    const app = await newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
    expect(res.text).toContain(`/score/${TEST_SCORE_TOKEN}/reset`)
    expect(res.text).toContain('confirm(')
    expect(res.text).toContain('?format=json')
  })
})
