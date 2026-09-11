const request = require('supertest')
const {
  newTestApp,
  registerAndLogin,
  sessionCookieToBearer,
  generateSelfSignedCert,
  signX5cToken,
  signArbitraryToken,
} = require('./helpers')

describe('POST /partner-api/sync-customers — rejection paths', () => {
  test('rejects the caller\'s own session token with 401', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    const res = await request(app)
      .post('/partner-api/sync-customers')
      .set('Authorization', `Bearer ${sessionCookieToBearer(cookie)}`)
    expect(res.status).toBe(401)
  })

  test('rejects a request with no Authorization header with 401', async () => {
    const app = newTestApp()
    const res = await request(app).post('/partner-api/sync-customers')
    expect(res.status).toBe(401)
  })

  test('rejects a well-formed but unrelated JWT with 401', async () => {
    const app = newTestApp()
    const token = signArbitraryToken({ partner_id: 'default-tier' })
    const res = await request(app)
      .post('/partner-api/sync-customers')
      .set('Authorization', `Bearer ${token}`)
    expect(res.status).toBe(401)
  })

  test('rejects a syntactically garbage x5c value without crashing', async () => {
    const app = newTestApp()
    const header = { alg: 'RS256', typ: 'JWT', x5c: ['not-valid-base64-der!!!'] }
    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url')
    const payloadB64 = Buffer.from(JSON.stringify({ partner_id: 'default-tier' })).toString('base64url')
    const token = `${headerB64}.${payloadB64}.fakesignature`
    const res = await request(app)
      .post('/partner-api/sync-customers')
      .set('Authorization', `Bearer ${token}`)
    expect(res.status).toBe(401)
  })
})

describe('POST /partner-api/sync-customers — the forgery', () => {
  test('accepts an x5c-forged token for an arbitrary partner_id and returns one customer record', async () => {
    const app = newTestApp()
    const cert = await generateSelfSignedCert()
    const token = signX5cToken({ partner_id: 'anything' }, cert)
    const res = await request(app)
      .post('/partner-api/sync-customers')
      .set('Authorization', `Bearer ${token}`)
    expect(res.status).toBe(200)
    expect(res.body.partner_id).toBe('anything')
    expect(res.body.customers.length).toBe(1)
  })

  test('accepts an x5c-forged token for partner_id: "acme-enterprise" and returns the full customer list', async () => {
    const app = newTestApp()
    const cert = await generateSelfSignedCert()
    const token = signX5cToken({ partner_id: 'acme-enterprise' }, cert)
    const res = await request(app)
      .post('/partner-api/sync-customers')
      .set('Authorization', `Bearer ${token}`)
    expect(res.status).toBe(200)
    expect(res.body.customers.length).toBe(6)
  })

  test('an unknown partner_id behaves like the default tier (single record, not an error)', async () => {
    const app = newTestApp()
    const cert = await generateSelfSignedCert()
    const token = signX5cToken({ partner_id: 'totally-unregistered' }, cert)
    const res = await request(app)
      .post('/partner-api/sync-customers')
      .set('Authorization', `Bearer ${token}`)
    expect(res.status).toBe(200)
    expect(res.body.customers.length).toBe(1)
  })

  test('a token signed by a different keypair than the one in its own x5c certificate is rejected', async () => {
    const app = newTestApp()
    const cert = await generateSelfSignedCert()
    const otherCert = await generateSelfSignedCert()
    const header = { alg: 'RS256', typ: 'JWT', x5c: [cert.certDer.toString('base64')] }
    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url')
    const payloadB64 = Buffer.from(JSON.stringify({ partner_id: 'anything' })).toString('base64url')
    const signingInput = `${headerB64}.${payloadB64}`
    const crypto = require('crypto')
    const signature = crypto.sign('RSA-SHA256', Buffer.from(signingInput), otherCert.privateKey)
    const token = `${signingInput}.${signature.toString('base64url')}`
    const res = await request(app)
      .post('/partner-api/sync-customers')
      .set('Authorization', `Bearer ${token}`)
    expect(res.status).toBe(401)
  })
})
