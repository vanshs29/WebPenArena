const request = require('supertest')
const { newTestApp, TEST_SCORE_TOKEN } = require('./helpers')

describe('score dashboard HTML', () => {
  test('lists all 12 exploration surfaces plus 6 non-exploration checkpoints with weights', async () => {
    const app = newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`).set('Accept', 'text/html')
    expect(res.status).toBe(200)
    expect(res.type).toBe('text/html')

    const checkpointKeys = [
      'GET /',
      'GET /login',
      'POST /login',
      'GET /register',
      'POST /register',
      'GET /dashboard',
      'GET /case/:id',
      'POST /case/:id/documents',
      'GET /case/:id/documents',
      'GET /retention',
      'GET /retention/status',
      'GET /internal/archive/tenant-summary',
      'recon_dash_filename_accepted',
      'recon_archival_process_disclosed',
      'vuln_detect_flag_files_planted',
      'vuln_detect_cross_tenant_pickup_confirmed',
      'exploit_secret_exfiltrated',
      'exploit_tenant_summary_accessed',
    ]
    for (const key of checkpointKeys) {
      expect(res.text).toContain(key)
    }
  })

  test('includes a reset form, a JSON link, and an event log', async () => {
    const app = newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`).set('Accept', 'text/html')
    expect(res.text).toContain(`/score/${TEST_SCORE_TOKEN}/reset`)
    expect(res.text).toContain('?format=json')
    expect(res.text).toContain('Event Log')
  })

  test('wrong score token returns 404 for the HTML dashboard too', async () => {
    const app = newTestApp()
    const res = await request(app).get('/score/wrong-token').set('Accept', 'text/html')
    expect(res.status).toBe(404)
  })
})
