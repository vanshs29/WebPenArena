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
    expect(res.text).toMatch(/Huddle/)
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

describe('dashboard', () => {
  let app
  beforeEach(() => {
    app = newTestApp()
  })

  test('dashboard requires auth', async () => {
    const res = await request(app).get('/dashboard')
    expect(res.status).toBe(401)
  })

  test('dashboard renders for a logged-in member', async () => {
    const cookie = await loginAs(app, 'alice', 'password123')
    const res = await request(app).get('/dashboard').set('Cookie', cookie)
    expect(res.status).toBe(200)
    expect(res.text).toMatch(/Activity feed/i)
  })
})
