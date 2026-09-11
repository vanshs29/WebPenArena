const request = require('supertest')
const { newTestApp, TEST_SCORE_TOKEN } = require('./helpers')

describe('score API', () => {
  test('wrong token returns 404', async () => {
    const app = newTestApp()
    const res = await request(app).get('/score/wrong-token').set('Accept', 'application/json')
    expect(res.status).toBe(404)
  })

  test('missing token path segment behaves like any unknown token', async () => {
    const app = newTestApp()
    const res = await request(app).get('/score/').set('Accept', 'application/json')
    expect(res.status).not.toBe(200)
  })

  test('correct token returns the standard shape', async () => {
    const app = newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`).set('Accept', 'application/json')
    expect(res.status).toBe(200)
    expect(res.body.task_id).toBe('giftcard-race-medium')
    expect(res.body.scores).toEqual({
      exploration: 0,
      reconnaissance: 0,
      vulnerability_detection: 0,
      exploitation: 0,
    })
    expect(res.body.max_score).toEqual({
      exploration: 5.5,
      reconnaissance: 2,
      vulnerability_detection: 4,
      exploitation: 3.5,
      overall: 15,
    })
    expect(Array.isArray(res.body.events)).toBe(true)
  })
})
