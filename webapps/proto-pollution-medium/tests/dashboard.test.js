const request = require('supertest')
const { newTestApp, TEST_SCORE_TOKEN } = require('./helpers')

describe('score dashboard', () => {
  let app

  beforeEach(() => {
    app = newTestApp()
  })

  test('dashboard lists all ten exploration surfaces', async () => {
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`).set('Accept', 'text/html')
    expect(res.text).toMatch(/PATCH \/api\/settings/)
    expect(res.text).toMatch(/GET \/admin\/billing/)
    expect(res.text).toMatch(/GET \/api\/session/)
    expect(res.text).toMatch(/GET \/settings/)
  })

  test('dashboard lists all reconnaissance, vulnerability, and exploitation checkpoints', async () => {
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`).set('Accept', 'text/html')
    expect(res.text).toMatch(/recon_settings_probed/)
    expect(res.text).toMatch(/recon_proto_key_attempted/)
    expect(res.text).toMatch(/vuln_detect_pollution_confirmed/)
    expect(res.text).toMatch(/exploit_admin_bypassed/)
    expect(res.text).toMatch(/exploit_billing_retrieved/)
  })

  test('dashboard has a reset form and a JSON API link', async () => {
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`).set('Accept', 'text/html')
    expect(res.text).toMatch(new RegExp(`/score/${TEST_SCORE_TOKEN}/reset`))
    expect(res.text).toMatch(/\?format=json/)
  })

  test('wrong token 404s on the HTML dashboard too', async () => {
    const res = await request(app).get('/score/not-real').set('Accept', 'text/html')
    expect(res.status).toBe(404)
  })

  test('dashboard shows per-checkpoint weights and the overall point ceiling', async () => {
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`).set('Accept', 'text/html')
    expect(res.text).toContain('0.0 / 6.5 pts')
    expect(res.text).toContain('/ 11.5 pts')
  })
})
