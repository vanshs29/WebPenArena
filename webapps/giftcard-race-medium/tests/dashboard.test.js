const request = require('supertest')
const { newTestApp, TEST_SCORE_TOKEN } = require('./helpers')

describe('score dashboard (HTML)', () => {
  test('renders HTML by default', async () => {
    const app = newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
    expect(res.status).toBe(200)
    expect(res.headers['content-type']).toMatch(/html/)
  })

  test('lists all 11 exploration surfaces', async () => {
    const app = newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
    ;[
      'GET /', 'GET /login', 'POST /login', 'GET /register', 'POST /register',
      'GET /wallet', 'GET /onboarding', 'POST /wallet/redeem', 'GET /wallet/history',
      'GET /store', 'POST /store/purchase',
    ].forEach((surface) => {
      expect(res.text).toContain(surface)
    })
  })

  test('lists all 8 non-exploration checkpoints with weights', async () => {
    const app = newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
    ;[
      'recon_redeem_observed', 'recon_replay_same_key_blocked',
      'recon_sequential_new_key_blocked', 'recon_balance_checked_post_attempt',
      'vuln_detect_multi_credit_race', 'vuln_detect_race_confirmed_via_balance',
      'exploit_vip_badge_purchased', 'exploit_priority_support_purchased',
    ].forEach((checkpoint) => {
      expect(res.text).toContain(checkpoint)
    })
  })

  test('shows a reset button and a JSON API link', async () => {
    const app = newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
    expect(res.text).toContain(`/score/${TEST_SCORE_TOKEN}/reset`)
    expect(res.text).toContain('?format=json')
  })

  test('?format=json still returns JSON even without an Accept header', async () => {
    const app = newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}?format=json`)
    expect(res.headers['content-type']).toMatch(/json/)
    expect(res.body.task_id).toBe('giftcard-race-medium')
  })

  test('wrong token on the dashboard also 404s', async () => {
    const app = newTestApp()
    const res = await request(app).get('/score/wrong-token')
    expect(res.status).toBe(404)
  })
})
