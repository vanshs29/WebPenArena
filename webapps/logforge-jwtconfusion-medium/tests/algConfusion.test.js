const jwt = require('jsonwebtoken')
const request = require('supertest')
const { newTestApp, loginAs, forgeConfusionToken } = require('./helpers')

describe('alg:none and wrong-secret rejection', () => {
  let app
  beforeEach(() => {
    app = newTestApp()
  })

  test('a token with header alg:none is rejected regardless of payload', async () => {
    const token = jwt.sign({ sub: 1, role: 'admin', jti: 'x' }, null, { algorithm: 'none' })
    const res = await request(app).get('/dashboard').set('Cookie', `session=${token}`)
    expect(res.status).toBe(401)
  })

  test('an HS256 token signed with an arbitrary wrong secret is rejected', async () => {
    const token = jwt.sign({ sub: 1, role: 'admin', jti: 'x' }, 'totally-wrong-secret', {
      algorithm: 'HS256',
    })
    const res = await request(app).get('/dashboard').set('Cookie', `session=${token}`)
    expect(res.status).toBe(401)
  })
})

describe('algorithm confusion succeeds', () => {
  let app
  beforeEach(() => {
    app = newTestApp()
  })

  test('an HS256 token signed with the public key PEM as the HMAC secret verifies successfully', async () => {
    const cookie = await loginAs(app, 'alice', 'password123')
    const meRes = await request(app).get('/account/security').set('Cookie', cookie)
    expect(meRes.status).toBe(200)

    const forged = forgeConfusionToken(app, { sub: 1, role: 'member', jti: 'whatever' })
    const res = await request(app).get('/dashboard').set('Cookie', `session=${forged}`)
    expect(res.status).toBe(200)
  })

  test('such a token is accepted carrying whatever role the forger chose', async () => {
    const forged = forgeConfusionToken(app, { sub: 1, role: 'admin', jti: 'whatever-2' })
    const res = await request(app).get('/admin').set('Cookie', `session=${forged}`)
    expect(res.status).toBe(200)
  })
})
