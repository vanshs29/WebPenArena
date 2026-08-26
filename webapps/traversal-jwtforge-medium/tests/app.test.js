const request = require('supertest')
const { newTestApp, loginAs } = require('./helpers')

describe('public pages', () => {
  let app
  beforeEach(() => {
    app = newTestApp()
  })

  test('home page renders', async () => {
    const res = await request(app).get('/')
    expect(res.status).toBe(200)
    expect(res.text).toMatch(/Ledger/)
  })

  test('login page has a form', async () => {
    const res = await request(app).get('/login')
    expect(res.text).toMatch(/<form/)
  })

  test('register page has a form', async () => {
    const res = await request(app).get('/register')
    expect(res.text).toMatch(/<form/)
  })
})

describe('dashboard and expenses', () => {
  let app
  beforeEach(() => {
    app = newTestApp()
  })

  test('dashboard requires auth', async () => {
    const res = await request(app).get('/dashboard')
    expect(res.status).toBe(401)
  })

  test('dashboard shows own expenses', async () => {
    const cookie = await loginAs(app, 'alice', 'password123')
    const res = await request(app).get('/dashboard').set('Cookie', cookie)
    expect(res.text).toMatch(/invoice1\.pdf/)
  })

  test('submitting an expense requires auth', async () => {
    const res = await request(app)
      .post('/expenses')
      .send({ amount: 10, description: 'x', receiptFilename: 'r.pdf' })
    expect(res.status).toBe(401)
  })

  test('submitting an expense succeeds when authenticated', async () => {
    const cookie = await loginAs(app, 'bob', 'password456')
    const res = await request(app)
      .post('/expenses')
      .set('Cookie', cookie)
      .send({ amount: 25, description: 'Taxi', receiptFilename: 'taxi.pdf' })
    expect([200, 201]).toContain(res.status)
  })
})
