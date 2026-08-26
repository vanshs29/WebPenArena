const request = require('supertest')
const { newTestApp, loginAs } = require('./helpers')

describe('receipts: normal use is safe', () => {
  let app
  beforeEach(() => {
    app = newTestApp()
  })

  test('viewing an existing receipt succeeds', async () => {
    const cookie = await loginAs(app, 'alice', 'password123')
    const res = await request(app).get('/receipts?file=invoice1.pdf').set('Cookie', cookie)
    expect(res.status).toBe(200)
  })

  test('viewing a nonexistent receipt returns 404', async () => {
    const cookie = await loginAs(app, 'alice', 'password123')
    const res = await request(app).get('/receipts?file=doesnotexist.pdf').set('Cookie', cookie)
    expect(res.status).toBe(404)
  })

  test('receipts endpoint requires auth', async () => {
    const res = await request(app).get('/receipts?file=invoice1.pdf')
    expect(res.status).toBe(401)
  })

  test('missing file param returns 400', async () => {
    const cookie = await loginAs(app, 'alice', 'password123')
    const res = await request(app).get('/receipts').set('Cookie', cookie)
    expect(res.status).toBe(400)
  })
})

describe('receipts: traversal works as designed', () => {
  let app
  beforeEach(() => {
    app = newTestApp()
  })

  test('traversal reaches the canary file', async () => {
    const cookie = await loginAs(app, 'alice', 'password123')
    const res = await request(app).get('/receipts?file=../config/canary.txt').set('Cookie', cookie)
    expect(res.status).toBe(200)
    expect(res.text).toMatch(/LEDGER_CONFIG_DIR_MARKER/)
  })

  test('traversal reaches the config file containing the JWT secret', async () => {
    const cookie = await loginAs(app, 'alice', 'password123')
    const res = await request(app).get('/receipts?file=../config/app-config.json').set('Cookie', cookie)
    expect(res.status).toBe(200)
    const body = JSON.parse(res.text)
    expect(body.jwtSecret).toBeDefined()
    expect(body.jwtSecret).toBe(app.locals.jwtSecret)
  })

  test('URL-encoded traversal sequence also works', async () => {
    const cookie = await loginAs(app, 'alice', 'password123')
    const res = await request(app).get('/receipts?file=%2e%2e%2fconfig%2fcanary.txt').set('Cookie', cookie)
    expect(res.status).toBe(200)
  })

  test('leaked config includes the full app config shape, not just the secret', async () => {
    const cookie = await loginAs(app, 'alice', 'password123')
    const res = await request(app).get('/receipts?file=../config/app-config.json').set('Cookie', cookie)
    const body = JSON.parse(res.text)
    expect(body.appName).toBe('Ledger')
    expect(body.environment).toBe('production')
  })

  test('a traversal attempt that resolves to nothing real still 404s', async () => {
    const cookie = await loginAs(app, 'alice', 'password123')
    const res = await request(app).get('/receipts?file=../nonexistent/nope.txt').set('Cookie', cookie)
    expect(res.status).toBe(404)
  })
})
