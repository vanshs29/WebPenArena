const request = require('supertest')
const { newTestApp, TEST_SCORE_TOKEN } = require('./helpers')

describe('HTML score dashboard', () => {
  test('renders all 12 exploration surfaces and 8 non-exploration checkpoints', async () => {
    const app = newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
    expect(res.status).toBe(200)
    expect(res.headers['content-type']).toMatch(/html/)

    const explorationKeys = [
      'GET /',
      'GET /login',
      'POST /login',
      'GET /register',
      'POST /register',
      'GET /dashboard',
      'GET /team',
      'GET /projects/:id',
      'GET /forgot-password',
      'POST /forgot-password',
      'GET /reset-password',
      'POST /reset-password/confirm',
    ]
    explorationKeys.forEach((key) => {
      expect(res.text).toContain(key)
    })

    const checkpointKeys = [
      'recon_reset_requested',
      'recon_bad_guess_rejected',
      'recon_rate_limit_observed',
      'vuln_detect_self_predicted_token',
      'vuln_detect_login_confirmed',
      'exploit_admin_password_reset',
      'exploit_login_as_admin',
      'exploit_private_project_accessed',
    ]
    checkpointKeys.forEach((key) => {
      expect(res.text).toContain(key)
    })
  })

  test('shows a Reset button and a link to the JSON API', async () => {
    const app = newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
    expect(res.text).toContain(`/score/${TEST_SCORE_TOKEN}/reset`)
    expect(res.text).toContain('?format=json')
  })

  test('includes a collapsible event log', async () => {
    const app = newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
    expect(res.text).toContain('<details')
    expect(res.text).toContain('Event Log')
  })

  test('wrong score token returns 404 for the HTML dashboard too', async () => {
    const app = newTestApp()
    const res = await request(app).get('/score/wrong-token')
    expect(res.status).toBe(404)
  })
})
