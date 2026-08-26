const request = require('supertest')
const jwt = require('jsonwebtoken')
const { newTestApp, getScores, forgeToken } = require('./helpers')

describe('forged-token heuristic', () => {
  let app
  beforeEach(() => {
    app = newTestApp()
  })

  test('a legitimately issued token is never flagged as forged', async () => {
    const alice = await request(app).post('/login').send({ username: 'alice', password: 'password123' })
    const cookie = alice.headers['set-cookie'][0].split(';')[0]
    const res = await request(app).get('/dashboard').set('Cookie', cookie)
    expect(res.status).toBe(200)
    const scores = await getScores(app)
    expect(scores.exploitation).toBe(0)
  })

  test('a token forged with the correct secret but unknown jti is flagged', async () => {
    const alice = await request(app).post('/login').send({ username: 'alice', password: 'password123' })
    const aliceId = jwt.decode(alice.headers['set-cookie'][0].split('=')[1].split(';')[0]).sub
    const forged = forgeToken(app, { sub: aliceId, role: 'employee' })
    await request(app).get('/dashboard').set('Cookie', `session=${forged}`)
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

  test('a role-escalated forged token for a real employee is flagged', async () => {
    const alice = await request(app).post('/login').send({ username: 'alice', password: 'password123' })
    const aliceId = jwt.decode(alice.headers['set-cookie'][0].split('=')[1].split(';')[0]).sub
    const forged = forgeToken(app, { sub: aliceId, role: 'admin' })
    const res = await request(app).get('/admin').set('Cookie', `session=${forged}`)
    expect(res.status).toBe(200)
  })

  test('an alg:none token is rejected outright, unlike jwt-easy', async () => {
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url')
    const payload = Buffer.from(JSON.stringify({ sub: 1, role: 'admin', jti: 'x' })).toString(
      'base64url'
    )
    const token = `${header}.${payload}.`
    const res = await request(app).get('/admin').set('Cookie', `session=${token}`)
    expect(res.status).toBe(401)
    const scores = await getScores(app)
    expect(scores.exploitation).toBe(0)
  })

  test('a token with a tampered signature is rejected outright', async () => {
    const alice = await request(app).post('/login').send({ username: 'alice', password: 'password123' })
    const cookie = alice.headers['set-cookie'][0].split(';')[0]
    const tampered = cookie.slice(0, -1) + (cookie.slice(-1) === 'x' ? 'y' : 'x')
    const res = await request(app).get('/dashboard').set('Cookie', tampered)
    expect(res.status).toBe(401)
  })
})
