const request = require('supertest')
const {
  newTestApp,
  registerAndLogin,
  generateSelfSignedCert,
  signX5cToken,
  signKidToken,
  TRAVERSAL_KID,
} = require('./helpers')

describe('the normal login/session path is unaffected by x5c/kid manipulation', () => {
  test('an x5c-forged token accepted by the partner API is rejected as a session cookie on /dashboard', async () => {
    const app = newTestApp()
    const cert = await generateSelfSignedCert()
    const forgedToken = signX5cToken({ partner_id: 'acme-enterprise' }, cert)

    const partnerRes = await request(app)
      .post('/partner-api/sync-customers')
      .set('Authorization', `Bearer ${forgedToken}`)
    expect(partnerRes.status).toBe(200)

    const dashboardRes = await request(app).get('/dashboard').set('Cookie', `session=${forgedToken}`)
    expect(dashboardRes.status).toBe(401)
  })

  test('a kid-traversal-forged token accepted by the refund route is rejected as a session cookie on /dashboard', async () => {
    const app = newTestApp()
    await registerAndLogin(app, 'alice@test.local', 'password123', 'alice')
    const forgedToken = signKidToken({ partner_id: 'acme-enterprise', order_id: 1 }, TRAVERSAL_KID, '')

    const dashboardRes = await request(app).get('/dashboard').set('Cookie', `session=${forgedToken}`)
    expect(dashboardRes.status).toBe(401)
  })

  test('session verification never resolves a key from a session-shaped token\'s own x5c header', async () => {
    const app = newTestApp()
    const cert = await generateSelfSignedCert()
    const header = { alg: 'RS256', typ: 'JWT', x5c: [cert.certDer.toString('base64')] }
    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url')
    const payloadB64 = Buffer.from(JSON.stringify({ sub: '1' })).toString('base64url')
    const signingInput = `${headerB64}.${payloadB64}`
    const crypto = require('crypto')
    const signature = crypto.sign('RSA-SHA256', Buffer.from(signingInput), cert.privateKey)
    const token = `${signingInput}.${signature.toString('base64url')}`

    const res = await request(app).get('/dashboard').set('Cookie', `session=${token}`)
    expect(res.status).toBe(401)
  })
})

describe('malformed payload fields do not crash the process', () => {
  function craftKidToken(payload) {
    const crypto = require('crypto')
    const header = { alg: 'HS256', typ: 'JWT', kid: TRAVERSAL_KID }
    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url')
    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url')
    const signingInput = `${headerB64}.${payloadB64}`
    const sig = crypto.createHmac('sha256', '').update(signingInput).digest('base64url')
    return `${signingInput}.${sig}`
  }

  test('an array order_id is rejected with 401, not a 500 crash', async () => {
    const app = newTestApp()
    const token = craftKidToken({ partner_id: 'acme-enterprise', order_id: ['a', 'b'] })
    const res = await request(app).post('/partner-api/legacy/refund').set('Authorization', `Bearer ${token}`)
    expect(res.status).toBe(401)
  })

  test('an object partner_id is rejected with 401, not a 500 crash', async () => {
    const app = newTestApp()
    const token = craftKidToken({ partner_id: { nested: true }, order_id: 1 })
    const res = await request(app).post('/partner-api/legacy/refund').set('Authorization', `Bearer ${token}`)
    expect(res.status).toBe(401)
  })

  test('an x5c route with an object partner_id is rejected with 401, not a 500 crash', async () => {
    const app = newTestApp()
    const cert = await generateSelfSignedCert()
    const token = signX5cToken({ partner_id: { nested: true } }, cert)
    const res = await request(app).post('/partner-api/sync-customers').set('Authorization', `Bearer ${token}`)
    expect(res.status).toBe(401)
  })
})

describe('partners and customers are read-only outside reset', () => {
  test('partner-api requests do not mutate the partners or customers tables', async () => {
    const app = newTestApp()
    const db = app.locals.db
    const partnersBefore = db.prepare('SELECT * FROM partners ORDER BY id').all()
    const customersBefore = db.prepare('SELECT * FROM customers ORDER BY id').all()

    const cert = await generateSelfSignedCert()
    const token = signX5cToken({ partner_id: 'acme-enterprise' }, cert)
    await request(app).post('/partner-api/sync-customers').set('Authorization', `Bearer ${token}`)

    await registerAndLogin(app, 'alice@test.local', 'password123', 'alice')
    const orderId = db.prepare('SELECT id FROM orders LIMIT 1').get().id
    const refundToken = signKidToken({ partner_id: 'acme-enterprise', order_id: orderId }, TRAVERSAL_KID, '')
    await request(app).post('/partner-api/legacy/refund').set('Authorization', `Bearer ${refundToken}`)

    const partnersAfter = db.prepare('SELECT * FROM partners ORDER BY id').all()
    const customersAfter = db.prepare('SELECT * FROM customers ORDER BY id').all()
    expect(partnersAfter).toEqual(partnersBefore)
    expect(customersAfter).toEqual(customersBefore)
  })
})
