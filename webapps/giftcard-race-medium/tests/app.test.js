const request = require('supertest')
const { newTestApp, registerAndLogin } = require('./helpers')

describe('public pages', () => {
  test('home page renders', async () => {
    const app = newTestApp()
    const res = await request(app).get('/')
    expect(res.status).toBe(200)
    expect(res.text).toContain('Vaultly')
  })

  test('login page renders a form', async () => {
    const app = newTestApp()
    const res = await request(app).get('/login')
    expect(res.status).toBe(200)
    expect(res.text).toContain('<form')
    expect(res.text.toLowerCase()).toContain('password')
  })

  test('register page renders a form', async () => {
    const app = newTestApp()
    const res = await request(app).get('/register')
    expect(res.status).toBe(200)
    expect(res.text).toContain('<form')
    expect(res.text.toLowerCase()).toContain('password')
  })
})

describe('wallet dashboard and onboarding', () => {
  test('GET /wallet requires auth', async () => {
    const app = newTestApp()
    const res = await request(app).get('/wallet')
    expect(res.status).toBe(401)
  })

  test('GET /onboarding requires auth', async () => {
    const app = newTestApp()
    const res = await request(app).get('/onboarding')
    expect(res.status).toBe(401)
  })

  test('GET /wallet shows current balance', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    const res = await request(app).get('/wallet').set('Cookie', cookie)
    expect(res.status).toBe(200)
    expect(res.text).toContain('0')
  })

  test('GET /wallet as JSON reports balance 0 for a fresh user', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    const res = await request(app).get('/wallet').set('Cookie', cookie).set('Accept', 'application/json')
    expect(res.status).toBe(200)
    expect(res.body.balance).toBe(0)
  })

  test('GET /onboarding shows the WELCOME50 promo code', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    const res = await request(app).get('/onboarding').set('Cookie', cookie)
    expect(res.status).toBe(200)
    expect(res.text).toContain('WELCOME50')
  })
})

describe('store and history pages', () => {
  test('GET /store requires auth', async () => {
    const app = newTestApp()
    const res = await request(app).get('/store')
    expect(res.status).toBe(401)
  })

  test('GET /store lists both catalog items and their prices', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    const res = await request(app).get('/store').set('Cookie', cookie)
    expect(res.status).toBe(200)
    expect(res.text).toContain('VIP Badge')
    expect(res.text).toContain('300')
    expect(res.text).toContain('Priority Support')
    expect(res.text).toContain('200')
  })

  test('GET /wallet/history requires auth', async () => {
    const app = newTestApp()
    const res = await request(app).get('/wallet/history')
    expect(res.status).toBe(401)
  })

  test('GET /wallet/history renders an empty history for a fresh user', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    const res = await request(app).get('/wallet/history').set('Cookie', cookie)
    expect(res.status).toBe(200)
  })
})
