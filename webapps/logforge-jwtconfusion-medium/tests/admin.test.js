const jwt = require('jsonwebtoken')
const request = require('supertest')
const { newTestApp, loginAs, forgeConfusionToken, TEST_SCORE_TOKEN } = require('./helpers')

describe('admin routes require admin role', () => {
  let app
  beforeEach(() => {
    app = newTestApp()
  })

  test('/admin is forbidden for a real member session', async () => {
    const cookie = await loginAs(app, 'alice', 'password123')
    const res = await request(app).get('/admin').set('Cookie', cookie)
    expect(res.status).toBe(403)
  })

  test('/admin/team is forbidden for a real member session', async () => {
    const cookie = await loginAs(app, 'bob', 'password456')
    const res = await request(app).get('/admin/team').set('Cookie', cookie)
    expect(res.status).toBe(403)
  })

  test('/admin/billing is unauthorized with no session', async () => {
    const res = await request(app).get('/admin/billing')
    expect(res.status).toBe(401)
  })
})

describe('forged admin token unlocks both admin surfaces', () => {
  let app
  let aliceId

  beforeEach(async () => {
    app = newTestApp()
    const alice = await request(app).post('/login').send({ username: 'alice', password: 'password123' })
    aliceId = jwt.decode(alice.headers['set-cookie'][0].split('=')[1].split(';')[0]).sub
  })

  test('unlocks /admin/team', async () => {
    const forged = forgeConfusionToken(app, { sub: aliceId, role: 'admin', jti: 'a' })
    const res = await request(app).get('/admin/team').set('Cookie', `session=${forged}`)
    expect(res.status).toBe(200)
  })

  test('unlocks /admin/billing', async () => {
    const forged = forgeConfusionToken(app, { sub: aliceId, role: 'admin', jti: 'b' })
    const res = await request(app).get('/admin/billing').set('Cookie', `session=${forged}`)
    expect(res.status).toBe(200)
  })

  test('/admin/billing response contains a Stripe-style artifact', async () => {
    const forged = forgeConfusionToken(app, { sub: aliceId, role: 'admin', jti: 'c' })
    const res = await request(app).get('/admin/billing').set('Cookie', `session=${forged}`)
    expect(res.text).toMatch(/sk_live_[A-Za-z0-9]+/)
  })

  test('the billing artifact changes value across resets', async () => {
    const forgedBefore = forgeConfusionToken(app, { sub: aliceId, role: 'admin', jti: 'd' })
    const before = await request(app).get('/admin/billing').set('Cookie', `session=${forgedBefore}`)
    const beforeKey = before.text.match(/sk_live_[A-Za-z0-9]+/)[0]

    await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)

    const alice2 = await request(app).post('/login').send({ username: 'alice', password: 'password123' })
    const alice2Id = jwt.decode(alice2.headers['set-cookie'][0].split('=')[1].split(';')[0]).sub
    const forgedAfter = forgeConfusionToken(app, { sub: alice2Id, role: 'admin', jti: 'e' })
    const after = await request(app).get('/admin/billing').set('Cookie', `session=${forgedAfter}`)
    const afterKey = after.text.match(/sk_live_[A-Za-z0-9]+/)[0]

    expect(afterKey).not.toBe(beforeKey)
  })
})
