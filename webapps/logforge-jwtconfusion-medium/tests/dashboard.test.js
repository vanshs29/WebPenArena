const request = require('supertest')
const { newTestApp, TEST_SCORE_TOKEN } = require('./helpers')

describe('HTML score dashboard', () => {
  let app
  beforeEach(() => {
    app = newTestApp()
  })

  test('wrong token returns 404', async () => {
    const res = await request(app).get('/score/wrong-token').set('Accept', 'text/html')
    expect(res.status).toBe(404)
  })

  test('lists all 13 exploration surfaces', async () => {
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`).set('Accept', 'text/html')
    expect(res.status).toBe(200)
    for (const surface of [
      'GET /',
      'GET /login',
      'POST /login',
      'GET /register',
      'POST /register',
      'GET /dashboard',
      'GET /feed',
      'POST /feed',
      'GET /account/security',
      'GET /keys/verify.pem',
      'GET /admin',
      'GET /admin/team',
      'GET /admin/billing',
    ]) {
      expect(res.text).toContain(surface)
    }
  })

  test('lists all 8 non-exploration checkpoints', async () => {
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`).set('Accept', 'text/html')
    for (const key of [
      'recon_feed_format_observed',
      'recon_admin_gate_confirmed',
      'recon_hs256_acceptance_probed',
      'vuln_detect_delimiter_break_confirmed',
      'vuln_detect_alg_confusion_token_accepted',
      'exploit_forged_log_line_rendered',
      'exploit_team_management_accessed',
      'exploit_billing_accessed',
    ]) {
      expect(res.text).toContain(key)
    }
  })

  test('shows a Reset button and a JSON API link', async () => {
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`).set('Accept', 'text/html')
    expect(res.text).toMatch(/Reset/i)
    expect(res.text).toMatch(/\?format=json/)
  })

  test('shows the overall design-time ceiling of 16.0', async () => {
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`).set('Accept', 'text/html')
    expect(res.text).toMatch(/16(\.0)?/)
  })
})
