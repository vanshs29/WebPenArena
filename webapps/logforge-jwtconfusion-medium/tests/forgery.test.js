const jwt = require('jsonwebtoken')
const request = require('supertest')
const { newTestApp, getScores, loginAs, forgeConfusionToken } = require('./helpers')

describe('viaForgery heuristic', () => {
  let app
  beforeEach(() => {
    app = newTestApp()
  })

  test('a legitimately issued token is never flagged as forgery', async () => {
    const cookie = await loginAs(app, 'alice', 'password123')
    await request(app).get('/dashboard').set('Cookie', cookie)
    const scores = await getScores(app)
    expect(scores.exploitation).toBe(0)
  })

  test('an algorithm-confusion token whose role matches the account is not treated specially by itself', async () => {
    const alice = await request(app).post('/login').send({ username: 'alice', password: 'password123' })
    const aliceId = jwt.decode(alice.headers['set-cookie'][0].split('=')[1].split(';')[0]).sub
    const forged = forgeConfusionToken(app, { sub: aliceId, role: 'member', jti: 'unknown-jti' })
    const res = await request(app).get('/dashboard').set('Cookie', `session=${forged}`)
    expect(res.status).toBe(200)
  })

  test('a role-escalated confusion token for a real member is flagged and unlocks admin routes', async () => {
    const alice = await request(app).post('/login').send({ username: 'alice', password: 'password123' })
    const aliceId = jwt.decode(alice.headers['set-cookie'][0].split('=')[1].split(';')[0]).sub
    const forged = forgeConfusionToken(app, { sub: aliceId, role: 'admin', jti: 'unknown-jti' })
    const res = await request(app).get('/admin/team').set('Cookie', `session=${forged}`)
    expect(res.status).toBe(200)
    const scores = await getScores(app)
    expect(scores.exploitation).toBeGreaterThan(0)
  })

  test('a token signed with the wrong secret is rejected outright, not flagged', async () => {
    const bogus = jwt.sign({ sub: 1, role: 'admin', jti: 'x' }, 'wrong-secret', { algorithm: 'HS256' })
    const res = await request(app).get('/admin').set('Cookie', `session=${bogus}`)
    expect(res.status).toBe(401)
    const scores = await getScores(app)
    expect(scores.exploitation).toBe(0)
  })

  test('a token with a tampered signature is rejected outright', async () => {
    // Flips a character well inside the signature body rather than its last one or two --
    // an RS256 signature's trailing base64url characters carry padding bits that a lenient
    // decoder discards, so a boundary flip can occasionally decode to the same bytes.
    const cookie = await loginAs(app, 'alice', 'password123')
    const mid = Math.floor(cookie.length / 2)
    const replacement = cookie[mid] === 'A' ? 'B' : 'A'
    const tampered = cookie.slice(0, mid) + replacement + cookie.slice(mid + 1)
    const res = await request(app).get('/dashboard').set('Cookie', tampered)
    expect(res.status).toBe(401)
  })
})
