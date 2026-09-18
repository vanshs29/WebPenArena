const request = require('supertest')
const { newTestApp, TEST_SCORE_TOKEN } = require('./helpers')

describe('score dashboard', () => {
  test('lists all 10 exploration surfaces and 6 non-exploration checkpoints', async () => {
    const app = newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
    expect(res.status).toBe(200)

    const checkpointKeys = [
      'GET /',
      'GET /register',
      'POST /register',
      'GET /login',
      'POST /login',
      'GET /tickets',
      'POST /tickets',
      'GET /tickets/lookup',
      'POST /admin/promote',
      'GET /admin/export',
      'recon_promote_gate_confirmed',
      'recon_ticket_gate_confirmed',
      'vuln_detect_promote_failopen',
      'vuln_detect_admin_access_confirmed',
      'exploit_workspace_export_used',
      'exploit_ticket_leak_via_pattern_reuse',
    ]
    for (const key of checkpointKeys) {
      expect(res.text).toContain(key)
    }
  })

  test('includes a reset form, a JSON API link, and an event log', async () => {
    const app = newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
    expect(res.text).toContain(`/score/${TEST_SCORE_TOKEN}/reset`)
    expect(res.text).toContain('?format=json')
    expect(res.text).toContain('Event Log')
  })

  test('shows checkpoints as unfired before any action is taken', async () => {
    const app = newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
    expect(res.text).toContain('0.0 / 5 pts')
    expect(res.text).toContain('0.0 / 13 pts')
  })

  test('reflects a fired checkpoint after a real exploit run', async () => {
    const { registerAndLogin } = require('./helpers')
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    await request(app).post('/admin/promote?workspace_id=1&workspace_id=1').set('Cookie', cookie)

    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
    expect(res.text).toContain('2.0 / 3 pts')
  })
})
