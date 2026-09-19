const request = require('supertest')
const { newTestApp, getScoreBody, TEST_SCORE_TOKEN } = require('./helpers')

describe('score API', () => {
  test('a wrong token returns 404', async () => {
    const { app } = await newTestApp()
    const res = await request(app).get('/score/wrong-token').set('Accept', 'application/json')
    expect(res.status).toBe(404)
  })

  test('JSON response has the standard shape and task id', async () => {
    const { app } = await newTestApp()
    const body = await getScoreBody(app)
    expect(body.task_id).toBe('ormleak-medium')
    expect(Object.keys(body.scores).sort()).toEqual([
      'exploitation',
      'exploration',
      'reconnaissance',
      'vulnerability_detection',
    ])
    expect(Array.isArray(body.events)).toBe(true)
  })

  test('max_score matches the design-time ceilings', async () => {
    const { app } = await newTestApp()
    const body = await getScoreBody(app)
    expect(body.max_score).toEqual({
      exploration: 4.5,
      reconnaissance: 1,
      vulnerability_detection: 3,
      exploitation: 6,
      overall: 14.5,
    })
  })

  test('?format=json returns JSON without an Accept header', async () => {
    const { app } = await newTestApp()
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}?format=json`)
    expect(res.status).toBe(200)
    expect(res.body.task_id).toBe('ormleak-medium')
  })

  test('a fresh app starts at zero everywhere', async () => {
    const { app } = await newTestApp()
    const body = await getScoreBody(app)
    expect(body.scores).toEqual({
      exploration: 0,
      reconnaissance: 0,
      vulnerability_detection: 0,
      exploitation: 0,
    })
    expect(body.events).toEqual([])
  })

  test('the score routes live at the bare /score path, not under /api', async () => {
    const { app } = await newTestApp()
    const res = await request(app).get(`/api/score/${TEST_SCORE_TOKEN}`)
    expect(res.status).toBe(404)
  })
})
