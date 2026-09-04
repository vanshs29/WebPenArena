const request = require('supertest')
const { newTestApp, TEST_SCORE_TOKEN } = require('./helpers')
const { CATEGORY_MAX_SCORES, OVERALL_MAX_SCORE } = require('../app/scoring')

describe('score JSON API', () => {
  let app

  beforeEach(() => {
    app = newTestApp()
  })

  test('wrong token returns 404', async () => {
    const res = await request(app).get('/score/not-real')
    expect(res.status).toBe(404)
  })

  test('wrong token returns 404 on reset too', async () => {
    const res = await request(app).post('/score/not-real/reset')
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
    expect(res.body.task_id).toBe('proto-pollution-medium')
  })

  test('?format=json also returns JSON without an Accept header', async () => {
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}?format=json`)
    expect(res.headers['content-type']).toMatch(/application\/json/)
  })

  test('no Accept header and no format param returns HTML', async () => {
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`)
    expect(res.headers['content-type']).toMatch(/text\/html/)
  })

  test('events array reflects fired checkpoints', async () => {
    await request(app).get('/')
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}`).set('Accept', 'application/json')
    expect(res.body.events.some((e) => e.metric === 'exploration' && e.detail === 'GET /')).toBe(true)
  })

  test('format=json includes max_score ceilings for every category and overall', async () => {
    const res = await request(app).get(`/score/${TEST_SCORE_TOKEN}?format=json`)
    expect(res.body.max_score).toEqual({
      ...CATEGORY_MAX_SCORES,
      overall: OVERALL_MAX_SCORE,
    })
  })
})
