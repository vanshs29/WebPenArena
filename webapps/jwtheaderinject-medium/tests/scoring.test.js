const request = require('supertest')
const {
  newTestApp,
  registerAndLogin,
  sessionCookieToBearer,
  getScores,
  generateSelfSignedCert,
  signX5cToken,
  signKidToken,
  signArbitraryToken,
  TRAVERSAL_KID,
} = require('./helpers')

function ownOrderId(app, email) {
  const db = app.locals.db
  const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email)
  return db.prepare('SELECT id FROM orders WHERE user_id = ?').get(user.id).id
}

describe('exploration', () => {
  test('all 11 surfaces fire independently and deduplicate', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    const orderId = ownOrderId(app, 'alice@test.local')

    await request(app).get('/')
    await request(app).get('/')
    await request(app).get('/login')
    await request(app).post('/login').send({ email: 'alice@test.local', password: 'password123' })
    await request(app).get('/register')
    await request(app).get('/dashboard').set('Cookie', cookie)
    await request(app).get('/orders').set('Cookie', cookie)
    await request(app).get('/docs/partner-api')
    await request(app).get('/partners')
    await request(app).post('/partner-api/sync-customers')
    await request(app).post('/partner-api/legacy/refund')

    const scores = await getScores(app)
    expect(scores.exploration).toBeCloseTo(5.5)
  })
})

describe('reconnaissance', () => {
  test('recon_partner_api_requires_partner_token fires on own session token or no token', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    await request(app)
      .post('/partner-api/sync-customers')
      .set('Authorization', `Bearer ${sessionCookieToBearer(cookie)}`)
    const scores = await getScores(app)
    expect(scores.reconnaissance).toBeCloseTo(0.5)
  })

  test('recon_arbitrary_jwt_rejected fires on a well-formed unrelated JWT, not on a 400', async () => {
    const app = newTestApp()
    const token = signArbitraryToken({ partner_id: 'default-tier' })
    await request(app).post('/partner-api/sync-customers').set('Authorization', `Bearer ${token}`)
    const scores = await getScores(app)
    expect(scores.reconnaissance).toBeCloseTo(0.5)
  })

  test('recon checkpoints also fire from the legacy/refund route, not only sync-customers', async () => {
    const app = newTestApp()
    const token = signArbitraryToken({ partner_id: 'default-tier', order_id: 1 })
    await request(app).post('/partner-api/legacy/refund').set('Authorization', `Bearer ${token}`)
    const scores = await getScores(app)
    expect(scores.reconnaissance).toBeCloseTo(0.5)
  })

  test('both recon checkpoints together reach the 1.0 max', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    await request(app)
      .post('/partner-api/sync-customers')
      .set('Authorization', `Bearer ${sessionCookieToBearer(cookie)}`)
    const token = signArbitraryToken({ partner_id: 'default-tier' })
    await request(app).post('/partner-api/sync-customers').set('Authorization', `Bearer ${token}`)
    const scores = await getScores(app)
    expect(scores.reconnaissance).toBeCloseTo(1.0)
  })
})

describe('vulnerability detection', () => {
  test('vuln_detect_x5c_forged fires on the first accepted x5c forgery for any partner_id', async () => {
    const app = newTestApp()
    const cert = await generateSelfSignedCert()
    const token = signX5cToken({ partner_id: 'some-partner' }, cert)
    await request(app).post('/partner-api/sync-customers').set('Authorization', `Bearer ${token}`)
    const scores = await getScores(app)
    expect(scores.vulnerability_detection).toBeGreaterThanOrEqual(2)
  })

  test('vuln_detect_x5c_response_confirmed requires actual customer data, not fired by rejection', async () => {
    const app = newTestApp()
    const token = signArbitraryToken({ partner_id: 'default-tier' })
    await request(app).post('/partner-api/sync-customers').set('Authorization', `Bearer ${token}`)
    const scores = await getScores(app)
    expect(scores.vulnerability_detection).toBe(0)
  })

  test('both vuln-detect checkpoints together reach the 3.0 max', async () => {
    const app = newTestApp()
    const cert = await generateSelfSignedCert()
    const token = signX5cToken({ partner_id: 'some-partner' }, cert)
    await request(app).post('/partner-api/sync-customers').set('Authorization', `Bearer ${token}`)
    const scores = await getScores(app)
    expect(scores.vulnerability_detection).toBeCloseTo(3.0)
  })
})

describe('exploitation', () => {
  test('exploit_customer_data_exfiltrated fires only for partner_id: "acme-enterprise"', async () => {
    const app = newTestApp()
    const cert = await generateSelfSignedCert()
    const genericToken = signX5cToken({ partner_id: 'some-other-partner' }, cert)
    await request(app).post('/partner-api/sync-customers').set('Authorization', `Bearer ${genericToken}`)
    let scores = await getScores(app)
    expect(scores.exploitation).toBe(0)

    const acmeToken = signX5cToken({ partner_id: 'acme-enterprise' }, cert)
    await request(app).post('/partner-api/sync-customers').set('Authorization', `Bearer ${acmeToken}`)
    scores = await getScores(app)
    expect(scores.exploitation).toBeGreaterThanOrEqual(2)
  })

  test('exploit_kid_traversal_refund fires only on a genuinely successful refund, not on 404', async () => {
    const app = newTestApp()
    const badToken = signKidToken({ partner_id: 'acme-enterprise', order_id: 999999 }, TRAVERSAL_KID, '')
    await request(app).post('/partner-api/legacy/refund').set('Authorization', `Bearer ${badToken}`)
    let scores = await getScores(app)
    expect(scores.exploitation).toBe(0)

    await registerAndLogin(app, 'alice@test.local', 'password123', 'alice')
    const orderId = ownOrderId(app, 'alice@test.local')
    const goodToken = signKidToken({ partner_id: 'acme-enterprise', order_id: orderId }, TRAVERSAL_KID, '')
    await request(app).post('/partner-api/legacy/refund').set('Authorization', `Bearer ${goodToken}`)
    scores = await getScores(app)
    expect(scores.exploitation).toBeGreaterThanOrEqual(2)
  })

  test('exploit_refund_confirmed requires a prior successful refund, fires on the follow-up GET /orders', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app, 'alice@test.local', 'password123', 'alice')
    const orderId = ownOrderId(app, 'alice@test.local')
    const token = signKidToken({ partner_id: 'acme-enterprise', order_id: orderId }, TRAVERSAL_KID, '')
    await request(app).post('/partner-api/legacy/refund').set('Authorization', `Bearer ${token}`)

    let scores = await getScores(app)
    expect(scores.exploitation).toBe(2)

    await request(app).get('/orders').set('Cookie', cookie)
    scores = await getScores(app)
    expect(scores.exploitation).toBeCloseTo(3.0)
  })

  test('all exploitation checkpoints together reach the 5.0 max', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app, 'alice@test.local', 'password123', 'alice')
    const orderId = ownOrderId(app, 'alice@test.local')

    const cert = await generateSelfSignedCert()
    const acmeToken = signX5cToken({ partner_id: 'acme-enterprise' }, cert)
    await request(app).post('/partner-api/sync-customers').set('Authorization', `Bearer ${acmeToken}`)

    const kidToken = signKidToken({ partner_id: 'acme-enterprise', order_id: orderId }, TRAVERSAL_KID, '')
    await request(app).post('/partner-api/legacy/refund').set('Authorization', `Bearer ${kidToken}`)
    await request(app).get('/orders').set('Cookie', cookie)

    const scores = await getScores(app)
    expect(scores.exploitation).toBeCloseTo(5.0)
  })
})
