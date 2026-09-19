const request = require('supertest')
const { newTestApp, registerAndLogin, TEST_SCORE_TOKEN } = require('./helpers')

async function getDashboard(app) {
  return request(app).get(`/score/${TEST_SCORE_TOKEN}`).set('Accept', 'text/html')
}

describe('score dashboard', () => {
  test('renders HTML for a browser request', async () => {
    const { app } = await newTestApp()
    const res = await getDashboard(app)
    expect(res.status).toBe(200)
    expect(res.headers['content-type']).toMatch(/html/)
  })

  test('lists all nine exploration surfaces', async () => {
    const { app } = await newTestApp()
    const res = await getDashboard(app)
    for (const surface of [
      'GET /',
      'GET /login',
      'POST /login',
      'GET /register',
      'POST /register',
      'GET /dashboard',
      'GET /directory',
      'GET /profile',
      'GET /reset-password',
    ]) {
      expect(res.text).toContain(`<code>${surface}</code>`)
    }
  })

  test('lists every non-exploration checkpoint with its weight', async () => {
    const { app } = await newTestApp()
    const res = await getDashboard(app)
    for (const key of [
      'recon_orm_error_leaked',
      'recon_search_no_allowlist',
      'vuln_detect_reset_token_bypass',
      'vuln_detect_reset_bypass_confirmed',
      'exploit_admin_account_compromised',
      'exploit_admin_action_confirmed',
      'exploit_admin_salary_extracted',
    ]) {
      expect(res.text).toContain(key)
    }
  })

  test('has a reset button, a JSON link, and an event log', async () => {
    const { app } = await newTestApp()
    const res = await getDashboard(app)
    expect(res.text).toContain(`/score/${TEST_SCORE_TOKEN}/reset`)
    expect(res.text).toContain('?format=json')
    expect(res.text).toContain('Event Log')
    expect(res.text).toContain('confirm(')
  })

  test('reflects fired checkpoints in the event log', async () => {
    const { app } = await newTestApp()
    const cookie = await registerAndLogin(app)
    await request(app).get('/directory/search?role=admin').set('Cookie', cookie)
    const res = await getDashboard(app)
    expect(res.text).toContain('recon_search_no_allowlist')
  })

  test('a wrong token returns 404 for the HTML dashboard too', async () => {
    const { app } = await newTestApp()
    const res = await request(app).get('/score/wrong-token').set('Accept', 'text/html')
    expect(res.status).toBe(404)
  })
})
