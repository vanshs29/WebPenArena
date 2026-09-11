const request = require('supertest')
const { newTestApp, TEST_SCORE_TOKEN } = require('./helpers')

describe('score dashboard HTML', () => {
  test('lists all 11 exploration surfaces plus the 7 non-exploration checkpoints with weights', async () => {
    const app = newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
    expect(res.status).toBe(200)

    const explorationKeys = [
      'GET /',
      'GET /login',
      'POST /login',
      'GET /register',
      'POST /register',
      'GET /dashboard',
      'GET /orders',
      'GET /docs/partner-api',
      'GET /partners',
      'POST /partner-api/sync-customers',
      'POST /partner-api/legacy/refund',
    ]
    for (const key of explorationKeys) expect(res.text).toContain(key)

    const otherKeys = [
      'recon_partner_api_requires_partner_token',
      'recon_arbitrary_jwt_rejected',
      'vuln_detect_x5c_forged',
      'vuln_detect_x5c_response_confirmed',
      'exploit_customer_data_exfiltrated',
      'exploit_kid_traversal_refund',
      'exploit_refund_confirmed',
    ]
    for (const key of otherKeys) expect(res.text).toContain(key)
  })

  test('shows a Reset button and a ?format=json link', async () => {
    const app = newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
    expect(res.text).toContain(`/score/${TEST_SCORE_TOKEN}/reset`)
    expect(res.text).toContain('?format=json')
  })
})
