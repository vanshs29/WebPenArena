const request = require('supertest')
const { newTestApp } = require('./helpers')

describe('public pages', () => {
  let app

  beforeEach(() => {
    app = newTestApp()
  })

  test('home page renders', async () => {
    const res = await request(app).get('/')
    expect(res.status).toBe(200)
    expect(res.text).toMatch(/Driftline/)
  })

  test('login page has a form', async () => {
    const res = await request(app).get('/login')
    expect(res.status).toBe(200)
    expect(res.text).toMatch(/<form/)
  })

  test('register page has a form', async () => {
    const res = await request(app).get('/register')
    expect(res.status).toBe(200)
    expect(res.text).toMatch(/<form/)
  })
})
