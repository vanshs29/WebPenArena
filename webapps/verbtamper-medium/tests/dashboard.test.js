const request = require('supertest')
const { newTestApp, TEST_SCORE_TOKEN } = require('./helpers')

describe('score dashboard HTML', () => {
  test('lists all 10 exploration surfaces and 7 non-exploration checkpoints with weights', async () => {
    const app = newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
    expect(res.status).toBe(200)

    const explorationSurfaces = [
      'GET /',
      'GET /login',
      'POST /login',
      'GET /register',
      'POST /register',
      'GET /dashboard',
      'GET /team',
      'GET /admin/reports',
      'POST /admin/users/:id/role',
      'POST /admin/reports/export',
    ]
    explorationSurfaces.forEach((s) => expect(res.text).toContain(s))

    const checkpoints = [
      'recon_role_post_blocked',
      'recon_export_post_blocked',
      'vuln_detect_verb_tamper_role',
      'vuln_detect_role_change_confirmed',
      'exploit_self_promoted_to_admin',
      'exploit_admin_session_confirmed',
      'exploit_confidential_report_exported',
    ]
    checkpoints.forEach((c) => expect(res.text).toContain(c))
  })

  test('shows a Reset button and a JSON API link', async () => {
    const app = newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
    expect(res.text).toContain(`/score/${TEST_SCORE_TOKEN}/reset`)
    expect(res.text).toContain('?format=json')
  })
})
