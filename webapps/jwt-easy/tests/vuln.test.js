const request = require('supertest')
const { newTestApp, makeAlgNoneToken, makeHS256Token } = require('./helpers/testApp')

describe('JWT alg:none forgery', () => {
  test('alg:none admin token grants access to admin panel', async () => {
    const app = newTestApp()
    const token = makeAlgNoneToken({ sub: '0', role: 'admin' })
    const res = await request(app).get('/admin').set('Authorization', `Bearer ${token}`)
    expect(res.status).toBe(200)
  })

  test('admin response exposes the post moderation data', async () => {
    const app = newTestApp()
    const token = makeAlgNoneToken({ sub: '0', role: 'admin' })
    const res = await request(app).get('/admin').set('Authorization', `Bearer ${token}`)
    expect(res.text).toContain('Hello, DevBlog')
  })

  test('tampered HS256 token (wrong signature) is rejected', async () => {
    const app = newTestApp()
    const valid = makeHS256Token({ sub: '1', role: 'user' })
    const [h, , s] = valid.split('.')
    const badPayload = Buffer.from(JSON.stringify({ sub: '1', role: 'admin' })).toString('base64url')
    const tampered = `${h}.${badPayload}.${s}`
    const res = await request(app).get('/admin').set('Authorization', `Bearer ${tampered}`)
    expect(res.status).toBe(401)
  })

  test('alg:none token with user role is rejected from admin', async () => {
    const app = newTestApp()
    const token = makeAlgNoneToken({ sub: '0', role: 'user' })
    const res = await request(app).get('/admin').set('Authorization', `Bearer ${token}`)
    expect(res.status).toBe(401)
  })

  test('malformed token is rejected', async () => {
    const app = newTestApp()
    const res = await request(app).get('/admin').set('Authorization', 'Bearer not-a-jwt')
    expect(res.status).toBe(401)
  })
})
