const request = require('supertest')
const { newTestApp, loginAs } = require('./helpers')

describe('RSA key exposure', () => {
  let app
  beforeEach(() => {
    app = newTestApp()
  })

  test('/keys/verify.pem requires authentication', async () => {
    const res = await request(app).get('/keys/verify.pem')
    expect(res.status).toBe(401)
  })

  test('/keys/verify.pem returns PEM content beginning with the public key header', async () => {
    const cookie = await loginAs(app, 'alice', 'password123')
    const res = await request(app).get('/keys/verify.pem').set('Cookie', cookie)
    expect(res.status).toBe(200)
    expect(res.text.trim().startsWith('-----BEGIN PUBLIC KEY-----')).toBe(true)
  })

  test('the response never contains private-key PEM headers', async () => {
    const cookie = await loginAs(app, 'alice', 'password123')
    const res = await request(app).get('/keys/verify.pem').set('Cookie', cookie)
    expect(res.text).not.toMatch(/PRIVATE KEY/)
  })

  test('/account/security requires authentication', async () => {
    const res = await request(app).get('/account/security')
    expect(res.status).toBe(401)
  })

  test('/account/security shows the token algorithm and links to the key download', async () => {
    const cookie = await loginAs(app, 'alice', 'password123')
    const res = await request(app).get('/account/security').set('Cookie', cookie)
    expect(res.status).toBe(200)
    expect(res.text).toMatch(/RS256/)
    expect(res.text).toMatch(/\/keys\/verify\.pem/)
  })
})
