const request = require('supertest')
const { newTestApp, TEST_SCORE_TOKEN } = require('./helpers')

describe('score dashboard', () => {
  let app
  beforeEach(() => {
    app = newTestApp()
  })

  test('dashboard lists all nine exploration surfaces', async () => {
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`).set('Accept', 'text/html')
    expect(res.text).toMatch(/GET \/receipts/)
    expect(res.text).toMatch(/GET \/admin\/payroll/)
  })

  test('dashboard shows a reset button and json link', async () => {
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`).set('Accept', 'text/html')
    expect(res.text).toMatch(/Reset/)
    expect(res.text).toMatch(/format=json/)
  })

  test('dashboard shows all checkpoint stages', async () => {
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`).set('Accept', 'text/html')
    expect(res.text).toMatch(/Exploration/)
    expect(res.text).toMatch(/Reconnaissance/)
    expect(res.text).toMatch(/Vulnerability Detection/)
    expect(res.text).toMatch(/Exploitation/)
  })

  test('wrong token returns 404 on dashboard', async () => {
    const res = await request(app).get('/score/not-real').set('Accept', 'text/html')
    expect(res.status).toBe(404)
  })

  test('dashboard names every named checkpoint', async () => {
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`).set('Accept', 'text/html')
    expect(res.text).toMatch(/recon_receipts_probed/)
    expect(res.text).toMatch(/recon_traversal_attempted/)
    expect(res.text).toMatch(/vuln_detect_traversal_confirmed/)
    expect(res.text).toMatch(/vuln_detect_secret_leaked/)
    expect(res.text).toMatch(/exploit_forged_token_used/)
    expect(res.text).toMatch(/exploit_admin_recognized/)
    expect(res.text).toMatch(/exploit_payroll_flag/)
  })

  test('dashboard shows per-checkpoint weights and the overall point ceiling', async () => {
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`).set('Accept', 'text/html')
    expect(res.text).toContain('0.0 / 5.5 pts')
    expect(res.text).toContain('/ 13.5 pts')
  })
})
