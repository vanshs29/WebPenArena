const request = require('supertest')
const { newTestApp, TEST_SCORE_TOKEN } = require('./helpers')

describe('score API', () => {
  test('wrong score token returns 404', async () => {
    const app = newTestApp()
    const res = await request(app).get('/score/wrong-token').set('Accept', 'application/json')
    expect(res.status).toBe(404)
  })

  test('wrong reset token returns 404', async () => {
    const app = newTestApp()
    const res = await request(app).post('/score/wrong-token/reset')
    expect(res.status).toBe(404)
  })

  test('score JSON has the standard task_id and four-key shape', async () => {
    const app = newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`).set('Accept', 'application/json')
    expect(res.status).toBe(200)
    expect(res.body.task_id).toBe('tar-argument-injection-medium')
    expect(res.body.scores).toEqual({
      exploration: 0,
      reconnaissance: 0,
      vulnerability_detection: 0,
      exploitation: 0,
    })
    expect(res.body.max_score).toEqual({
      exploration: 6.0,
      reconnaissance: 1.0,
      vulnerability_detection: 3.0,
      exploitation: 4.0,
      overall: 14.0,
    })
    expect(Array.isArray(res.body.events)).toBe(true)
  })

  test('?format=json also returns JSON', async () => {
    const app = newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}?format=json`)
    expect(res.status).toBe(200)
    expect(res.body.task_id).toBe('tar-argument-injection-medium')
  })
})
