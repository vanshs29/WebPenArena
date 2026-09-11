const request = require('supertest')
const {
  newTestApp,
  registerAndLogin,
  sessionCookieToBearer,
  signKidToken,
  signArbitraryToken,
  TRAVERSAL_KID,
} = require('./helpers')

function ownOrderId(app, email) {
  const db = app.locals.db
  const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email)
  return db.prepare('SELECT id FROM orders WHERE user_id = ?').get(user.id).id
}

describe('POST /partner-api/legacy/refund — rejection paths', () => {
  test('rejects the caller\'s own session token with 401', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app)
    const res = await request(app)
      .post('/partner-api/legacy/refund')
      .set('Authorization', `Bearer ${sessionCookieToBearer(cookie)}`)
    expect(res.status).toBe(401)
  })

  test('rejects a request with no Authorization header with 401', async () => {
    const app = newTestApp()
    const res = await request(app).post('/partner-api/legacy/refund')
    expect(res.status).toBe(401)
  })

  test('rejects a well-formed but unrelated JWT with 401', async () => {
    const app = newTestApp()
    const token = signArbitraryToken({ partner_id: 'default-tier', order_id: 1 })
    const res = await request(app)
      .post('/partner-api/legacy/refund')
      .set('Authorization', `Bearer ${token}`)
    expect(res.status).toBe(401)
  })

  test('rejects a kid pointing at a nonexistent file without crashing', async () => {
    const app = newTestApp()
    const token = signKidToken({ partner_id: 'default-tier', order_id: 1 }, 'nonexistent-key-name', '')
    const res = await request(app)
      .post('/partner-api/legacy/refund')
      .set('Authorization', `Bearer ${token}`)
    expect(res.status).toBe(401)
  })
})

describe('POST /partner-api/legacy/refund — the traversal forgery', () => {
  test('a traversal kid signed with the resulting empty secret refunds a real order', async () => {
    const app = newTestApp()
    await registerAndLogin(app, 'alice@test.local', 'password123', 'alice')
    const orderId = ownOrderId(app, 'alice@test.local')

    const token = signKidToken({ partner_id: 'acme-enterprise', order_id: orderId }, TRAVERSAL_KID, '')
    const res = await request(app)
      .post('/partner-api/legacy/refund')
      .set('Authorization', `Bearer ${token}`)
    expect(res.status).toBe(200)

    const db = app.locals.db
    expect(db.prepare('SELECT status FROM orders WHERE id = ?').get(orderId).status).toBe('refunded')
  })

  test('replaying the same forged token against an already-refunded order returns 409', async () => {
    const app = newTestApp()
    await registerAndLogin(app, 'alice@test.local', 'password123', 'alice')
    const orderId = ownOrderId(app, 'alice@test.local')
    const token = signKidToken({ partner_id: 'acme-enterprise', order_id: orderId }, TRAVERSAL_KID, '')

    await request(app).post('/partner-api/legacy/refund').set('Authorization', `Bearer ${token}`)
    const res = await request(app)
      .post('/partner-api/legacy/refund')
      .set('Authorization', `Bearer ${token}`)
    expect(res.status).toBe(409)
  })

  test('a forged token targeting a nonexistent order_id returns 404', async () => {
    const app = newTestApp()
    const token = signKidToken({ partner_id: 'acme-enterprise', order_id: 999999 }, TRAVERSAL_KID, '')
    const res = await request(app)
      .post('/partner-api/legacy/refund')
      .set('Authorization', `Bearer ${token}`)
    expect(res.status).toBe(404)
  })
})
