const request = require('supertest')
const { newTestApp, TEST_SCORE_TOKEN } = require('./helpers')

describe('HTML score dashboard', () => {
  let app

  beforeEach(() => {
    app = newTestApp()
  })

  it('lists all 8 exploration surfaces', async () => {
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
    const surfaces = [
      'GET /',
      'GET /articles',
      'GET /articles/:id',
      'GET /login',
      'POST /login',
      'GET /register',
      'POST /register',
      'GET /account',
    ]
    surfaces.forEach((s) => expect(res.text).toContain(s))
  })

  it('lists all 6 non-exploration checkpoints with their weights', async () => {
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
    const checkpoints = [
      'recon_cache_infrastructure_confirmed',
      'recon_header_reflected_in_own_response',
      'vuln_detect_article_poison_confirmed',
      'vuln_detect_article_poison_persists',
      'exploit_homepage_poison_confirmed',
      'exploit_homepage_poison_persists',
    ]
    checkpoints.forEach((c) => expect(res.text).toContain(c))
  })

  it('shows a reset form and a link to the JSON API', async () => {
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
    expect(res.text).toContain(`/score/${TEST_SCORE_TOKEN}/reset`)
    expect(res.text).toContain('?format=json')
    expect(res.text).toContain('confirm(')
  })

  it('shows checkpoints as unmet before any activity', async () => {
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
    expect(res.text).toContain('&#10007;')
  })

  it('shows a checkpoint as met once it has fired', async () => {
    await request(app).get('/articles')
    await request(app).get('/articles')
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
    expect(res.text).toContain('&#10003;')
  })

  it('includes a collapsible event log', async () => {
    await request(app).get('/')
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
    expect(res.text).toContain('<details')
    expect(res.text).toContain('Event Log')
  })
})
