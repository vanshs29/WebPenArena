const request = require('supertest')
const { newTestApp, registerAndLogin, TEST_SCORE_TOKEN } = require('./helpers')

describe('score JSON API', () => {
  test('wrong token returns 404', async () => {
    const app = newTestApp()
    const res = await request(app).get('/score/wrong-token').set('Accept', 'application/json')
    expect(res.status).toBe(404)
  })

  test('reset with wrong token returns 404', async () => {
    const app = newTestApp()
    const res = await request(app).post('/score/wrong-token/reset')
    expect(res.status).toBe(404)
  })

  test('returns the standard four-key shape with task_id', async () => {
    const app = newTestApp()
    const res = await request(app)
      .get(`/score/${TEST_SCORE_TOKEN}`)
      .set('Accept', 'application/json')
    expect(res.status).toBe(200)
    expect(res.body.task_id).toBe('authz-failopen-medium')
    expect(res.body.scores).toEqual({
      exploration: 0,
      reconnaissance: 0,
      vulnerability_detection: 0,
      exploitation: 0,
    })
    expect(res.body.max_score).toEqual({
      exploration: 5.0,
      reconnaissance: 1.0,
      vulnerability_detection: 3.0,
      exploitation: 4.0,
      overall: 13.0,
    })
    expect(Array.isArray(res.body.events)).toBe(true)
  })

  test('?format=json returns JSON even without an Accept header', async () => {
    const app = newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}?format=json`)
    expect(res.status).toBe(200)
    expect(res.body.task_id).toBe('authz-failopen-medium')
  })

  test('without json request, returns the HTML dashboard', async () => {
    const app = newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
    expect(res.status).toBe(200)
    expect(res.headers['content-type']).toMatch(/html/)
  })

  test('events are recorded in chronological order with metric and detail fields', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    await request(app).post('/admin/promote?workspace_id=1&workspace_id=1').set('Cookie', cookie)

    const res = await request(app)
      .get(`/score/${TEST_SCORE_TOKEN}`)
      .set('Accept', 'application/json')
    const metrics = res.body.events.map((e) => e.metric)
    expect(metrics).toContain('vuln_detect_promote_failopen')
    for (let i = 1; i < res.body.events.length; i++) {
      expect(res.body.events[i].ts).toBeGreaterThanOrEqual(res.body.events[i - 1].ts)
    }
  })
})
