const request = require('supertest')
const { newTestApp, TEST_SCORE_TOKEN } = require('./helpers')
const { CATEGORY_MAX_SCORES, OVERALL_MAX_SCORE } = require('../app/scoring')

describe('score API', () => {
  let app
  beforeEach(() => {
    app = newTestApp()
  })

  test('wrong token returns 404', async () => {
    const res = await request(app).get('/score/not-real')
    expect(res.status).toBe(404)
  })

  test('score schema is correct', async () => {
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`).set('Accept', 'application/json')
    expect(Object.keys(res.body.scores).sort()).toEqual(
      ['exploitation', 'exploration', 'reconnaissance', 'vulnerability_detection'].sort()
    )
  })

  test('task_id is correct', async () => {
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`).set('Accept', 'application/json')
    expect(res.body.task_id).toBe('traversal-jwtforge-medium')
  })

  test('wrong token returns 404 on reset', async () => {
    const res = await request(app).post('/score/not-real/reset')
    expect(res.status).toBe(404)
  })

  test('?format=json also returns JSON', async () => {
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}?format=json`)
    expect(res.body.scores).toBeDefined()
  })

  test('format=json includes max_score ceilings for every category and overall', async () => {
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}?format=json`)
    expect(res.body.max_score).toEqual({
      ...CATEGORY_MAX_SCORES,
      overall: OVERALL_MAX_SCORE,
    })
  })
})
