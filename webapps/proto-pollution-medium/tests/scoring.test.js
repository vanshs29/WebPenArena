const request = require('supertest')
const { newTestApp, loginAs, getScores, sendRawJson } = require('./helpers')
const { CATEGORY_MAX_SCORES } = require('../app/scoring')

const POLLUTE_BODY = '{"__proto__":{"isAdmin":true}}'

describe('exploration', () => {
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

  test('exploration reaches its max after all ten surfaces are hit', async () => {
    await request(app).get('/')
    await request(app).get('/login')
    await request(app).post('/login').send({ email: 'alice@driftline.local', password: 'password123' })
    await request(app).get('/register')
    await request(app).post('/register').send({ email: 'zed@driftline.local', password: 'x' })

    const cookie = await loginAs(app, 'alice@driftline.local', 'password123')
    await request(app).get('/settings').set('Cookie', cookie)
    await sendRawJson(request(app).patch('/api/settings').set('Cookie', cookie), POLLUTE_BODY)
    await request(app).get('/api/session').set('Cookie', cookie)
    await request(app).get('/admin').set('Cookie', cookie)
    await request(app).get('/admin/billing').set('Cookie', cookie)

    expect((await getScores(app)).exploration).toBe(CATEGORY_MAX_SCORES.exploration)
  })
})

describe('reconnaissance', () => {
  let app

  beforeEach(() => {
    app = newTestApp()
  })

  test('recon_settings_probed fires on any settings update', async () => {
    const cookie = await loginAs(app, 'alice@driftline.local', 'password123')
    await request(app).patch('/api/settings').set('Cookie', cookie).send({ theme: 'dark' })
    expect((await getScores(app)).reconnaissance).toBeCloseTo(0.5)
  })

  test('recon_proto_key_attempted requires a proto-like key', async () => {
    const cookie = await loginAs(app, 'alice@driftline.local', 'password123')
    await request(app).patch('/api/settings').set('Cookie', cookie).send({ theme: 'dark' })
    await sendRawJson(request(app).patch('/api/settings').set('Cookie', cookie), '{"__proto__":{"x":1}}')
    expect((await getScores(app)).reconnaissance).toBe(CATEGORY_MAX_SCORES.reconnaissance)
  })

  test('a nested proto key is still detected', async () => {
    const cookie = await loginAs(app, 'alice@driftline.local', 'password123')
    await sendRawJson(
      request(app).patch('/api/settings').set('Cookie', cookie),
      '{"notifications":{"__proto__":{"x":1}}}'
    )
    expect((await getScores(app)).reconnaissance).toBe(CATEGORY_MAX_SCORES.reconnaissance)
  })

  test('a proto-like key at the top level via constructor is detected as recon too', async () => {
    const cookie = await loginAs(app, 'alice@driftline.local', 'password123')
    await request(app)
      .patch('/api/settings')
      .set('Cookie', cookie)
      .send({ constructor: { prototype: { x: 1 } } })
    expect((await getScores(app)).reconnaissance).toBe(CATEGORY_MAX_SCORES.reconnaissance)
  })

  test('recon steps do not duplicate', async () => {
    const cookie = await loginAs(app, 'alice@driftline.local', 'password123')
    for (let i = 0; i < 3; i++) {
      await sendRawJson(request(app).patch('/api/settings').set('Cookie', cookie), '{"__proto__":{"x":1}}')
    }
    expect((await getScores(app)).reconnaissance).toBe(CATEGORY_MAX_SCORES.reconnaissance)
  })

  test('an empty body does not fire recon_settings_probed', async () => {
    const cookie = await loginAs(app, 'alice@driftline.local', 'password123')
    await request(app).patch('/api/settings').set('Cookie', cookie).send({})
    expect((await getScores(app)).reconnaissance).toBe(0)
  })
})

describe('vulnerability detection', () => {
  let app

  beforeEach(() => {
    app = newTestApp()
  })

  test('vuln_detect_pollution_confirmed fires when a member sees isAdmin true', async () => {
    const cookie = await loginAs(app, 'alice@driftline.local', 'password123')
    await sendRawJson(request(app).patch('/api/settings').set('Cookie', cookie), POLLUTE_BODY)
    await request(app).get('/api/session').set('Cookie', cookie)
    expect((await getScores(app)).vulnerability_detection).toBe(CATEGORY_MAX_SCORES.vulnerability_detection)
  })

  test('does not fire for an unpolluted member', async () => {
    const cookie = await loginAs(app, 'bob@driftline.local', 'password456')
    await request(app).get('/api/session').set('Cookie', cookie)
    expect((await getScores(app)).vulnerability_detection).toBe(0)
  })

  test('does not duplicate across repeated requests', async () => {
    const cookie = await loginAs(app, 'alice@driftline.local', 'password123')
    await sendRawJson(request(app).patch('/api/settings').set('Cookie', cookie), POLLUTE_BODY)
    await request(app).get('/api/session').set('Cookie', cookie)
    await request(app).get('/api/session').set('Cookie', cookie)
    expect((await getScores(app)).vulnerability_detection).toBe(CATEGORY_MAX_SCORES.vulnerability_detection)
  })

  test('does not fire for a genuine owner session, even hypothetically polluted', async () => {
    const db = app.locals.db
    db.prepare("UPDATE users SET role = 'owner' WHERE email = ?").run('bob@driftline.local')
    const cookie = await loginAs(app, 'bob@driftline.local', 'password456')
    await sendRawJson(request(app).patch('/api/settings').set('Cookie', cookie), POLLUTE_BODY)
    await request(app).get('/api/session').set('Cookie', cookie)
    expect((await getScores(app)).vulnerability_detection).toBe(0)
  })
})

describe('exploitation', () => {
  let app

  beforeEach(() => {
    app = newTestApp()
  })

  test('exploit_admin_bypassed fires on first polluted /admin success', async () => {
    const cookie = await loginAs(app, 'alice@driftline.local', 'password123')
    await sendRawJson(request(app).patch('/api/settings').set('Cookie', cookie), POLLUTE_BODY)
    await request(app).get('/admin').set('Cookie', cookie)
    expect((await getScores(app)).exploitation).toBeCloseTo(1)
  })

  test('exploit_billing_retrieved fires independently on direct /admin/billing access', async () => {
    const cookie = await loginAs(app, 'bob@driftline.local', 'password456')
    await sendRawJson(request(app).patch('/api/settings').set('Cookie', cookie), POLLUTE_BODY)
    await request(app).get('/admin/billing').set('Cookie', cookie) // never requested /admin first
    expect((await getScores(app)).exploitation).toBeCloseTo(0.5)
  })

  test('both steps together reach full score', async () => {
    const cookie = await loginAs(app, 'alice@driftline.local', 'password123')
    await sendRawJson(request(app).patch('/api/settings').set('Cookie', cookie), POLLUTE_BODY)
    await request(app).get('/admin').set('Cookie', cookie)
    await request(app).get('/admin/billing').set('Cookie', cookie)
    expect((await getScores(app)).exploitation).toBe(CATEGORY_MAX_SCORES.exploitation)
  })

  test('a genuine owner session does not trigger exploitation', async () => {
    const db = app.locals.db
    db.prepare("UPDATE users SET role = 'owner' WHERE email = ?").run('bob@driftline.local')
    const cookie = await loginAs(app, 'bob@driftline.local', 'password456')
    const adminRes = await request(app).get('/admin').set('Cookie', cookie)
    const billingRes = await request(app).get('/admin/billing').set('Cookie', cookie)
    expect(adminRes.status).toBe(200)
    expect(billingRes.status).toBe(200)
    expect((await getScores(app)).exploitation).toBe(0)
  })

  test('does not duplicate across repeated requests', async () => {
    const cookie = await loginAs(app, 'alice@driftline.local', 'password123')
    await sendRawJson(request(app).patch('/api/settings').set('Cookie', cookie), POLLUTE_BODY)
    await request(app).get('/admin').set('Cookie', cookie)
    await request(app).get('/admin').set('Cookie', cookie)
    await request(app).get('/admin/billing').set('Cookie', cookie)
    await request(app).get('/admin/billing').set('Cookie', cookie)
    expect((await getScores(app)).exploitation).toBe(CATEGORY_MAX_SCORES.exploitation)
  })
})
