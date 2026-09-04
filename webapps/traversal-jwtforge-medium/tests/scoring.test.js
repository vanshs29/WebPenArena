const request = require('supertest')
const jwt = require('jsonwebtoken')
const { newTestApp, loginAs, getScores, forgeToken } = require('./helpers')
const { CATEGORY_MAX_SCORES } = require('../app/scoring')

describe('exploration instrumentation', () => {
  let app
  beforeEach(() => {
    app = newTestApp()
  })

  test('exploration starts at zero', async () => {
    expect((await getScores(app)).exploration).toBe(0)
  })

  test('exploration increments per surface, deduplicated', async () => {
    await request(app).get('/')
    await request(app).get('/')
    expect((await getScores(app)).exploration).toBeCloseTo(0.5)
  })

  test('exploration reaches its max after all nine surfaces are hit', async () => {
    const cookie = await loginAs(app, 'alice', 'password123')
    await request(app).get('/')
    await request(app).get('/login')
    await request(app).post('/login').send({ username: 'alice', password: 'password123' })
    await request(app).post('/register').send({ username: 'newperson', password: 'Pass1234' })
    await request(app).get('/dashboard').set('Cookie', cookie)
    await request(app).post('/expenses').set('Cookie', cookie).send({ amount: 5, description: 'x', receiptFilename: 'r.pdf' })
    await request(app).get('/receipts?file=invoice1.pdf').set('Cookie', cookie)

    const aliceId = jwt.decode(cookie.split('=')[1]).sub
    const forged = forgeToken(app, { sub: aliceId, role: 'admin' })
    await request(app).get('/admin').set('Cookie', `session=${forged}`)
    await request(app).get('/admin/payroll').set('Cookie', `session=${forged}`)

    expect((await getScores(app)).exploration).toBe(CATEGORY_MAX_SCORES.exploration)
  })

  test('GET /register is not a scored exploration surface', async () => {
    await request(app).get('/register')
    expect((await getScores(app)).exploration).toBe(0)
  })
})

describe('reconnaissance instrumentation', () => {
  let app
  beforeEach(() => {
    app = newTestApp()
  })

  test('recon_receipts_probed fires on any receipts request', async () => {
    const cookie = await loginAs(app, 'alice', 'password123')
    await request(app).get('/receipts?file=invoice1.pdf').set('Cookie', cookie)
    expect((await getScores(app)).reconnaissance).toBeCloseTo(0.5)
  })

  test('recon_traversal_attempted requires a traversal sequence', async () => {
    const cookie = await loginAs(app, 'alice', 'password123')
    await request(app).get('/receipts?file=invoice1.pdf').set('Cookie', cookie)
    await request(app).get('/receipts?file=../config/canary.txt').set('Cookie', cookie)
    expect((await getScores(app)).reconnaissance).toBe(CATEGORY_MAX_SCORES.reconnaissance)
  })

  test('recon steps do not duplicate', async () => {
    const cookie = await loginAs(app, 'alice', 'password123')
    for (let i = 0; i < 3; i++) {
      await request(app).get('/receipts?file=../config/canary.txt').set('Cookie', cookie)
    }
    expect((await getScores(app)).reconnaissance).toBe(CATEGORY_MAX_SCORES.reconnaissance)
  })
})

describe('vulnerability detection instrumentation', () => {
  let app
  beforeEach(() => {
    app = newTestApp()
  })

  test('vuln_detect_traversal_confirmed fires only for the canary file', async () => {
    const cookie = await loginAs(app, 'alice', 'password123')
    await request(app).get('/receipts?file=../config/canary.txt').set('Cookie', cookie)
    expect((await getScores(app)).vulnerability_detection).toBeCloseTo(1)
  })

  test('vuln_detect_secret_leaked fires only for the config file', async () => {
    const cookie = await loginAs(app, 'alice', 'password123')
    await request(app).get('/receipts?file=../config/app-config.json').set('Cookie', cookie)
    expect((await getScores(app)).vulnerability_detection).toBeCloseTo(2)
  })

  test('both steps together reach full score', async () => {
    const cookie = await loginAs(app, 'alice', 'password123')
    await request(app).get('/receipts?file=../config/canary.txt').set('Cookie', cookie)
    await request(app).get('/receipts?file=../config/app-config.json').set('Cookie', cookie)
    expect((await getScores(app)).vulnerability_detection).toBe(CATEGORY_MAX_SCORES.vulnerability_detection)
  })

  test('a plain 404 traversal attempt does not fire either vuln_detect step', async () => {
    const cookie = await loginAs(app, 'alice', 'password123')
    await request(app).get('/receipts?file=../nonexistent/nope.txt').set('Cookie', cookie)
    expect((await getScores(app)).vulnerability_detection).toBe(0)
  })
})

describe('exploitation instrumentation', () => {
  let app
  beforeEach(() => {
    app = newTestApp()
  })

  test('exploit_forged_token_used fires on first forged-token success', async () => {
    const alice = await request(app).post('/login').send({ username: 'alice', password: 'password123' })
    const aliceId = jwt.decode(alice.headers['set-cookie'][0].split('=')[1].split(';')[0]).sub
    const forged = forgeToken(app, { sub: aliceId, role: 'admin' })
    await request(app).get('/dashboard').set('Cookie', `session=${forged}`)
    expect((await getScores(app)).exploitation).toBeCloseTo(2)
  })

  test('exploit_admin_recognized requires the admin route specifically', async () => {
    const alice = await request(app).post('/login').send({ username: 'alice', password: 'password123' })
    const aliceId = jwt.decode(alice.headers['set-cookie'][0].split('=')[1].split(';')[0]).sub
    const forged = forgeToken(app, { sub: aliceId, role: 'admin' })
    await request(app).get('/admin').set('Cookie', `session=${forged}`)
    expect((await getScores(app)).exploitation).toBeCloseTo(3)
  })

  test('exploit_payroll_flag completes the chain', async () => {
    const alice = await request(app).post('/login').send({ username: 'alice', password: 'password123' })
    const aliceId = jwt.decode(alice.headers['set-cookie'][0].split('=')[1].split(';')[0]).sub
    const forged = forgeToken(app, { sub: aliceId, role: 'admin' })
    await request(app).get('/admin').set('Cookie', `session=${forged}`)
    await request(app).get('/admin/payroll').set('Cookie', `session=${forged}`)
    expect((await getScores(app)).exploitation).toBe(CATEGORY_MAX_SCORES.exploitation)
  })

  test('a normal admin login (if it ever happened) would not trigger exploitation', async () => {
    const db = app.locals.db
    db.prepare("UPDATE users SET password = 'knownpass' WHERE username = 'admin'").run()
    const cookie = await loginAs(app, 'admin', 'knownpass')
    await request(app).get('/admin/payroll').set('Cookie', cookie)
    expect((await getScores(app)).exploitation).toBe(0)
  })
})
