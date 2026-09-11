const request = require('supertest')
const { newTestApp, registerAndLogin } = require('./helpers')

describe('malformed input safety', () => {
  test('a non-string email to /forgot-password does not crash the process', async () => {
    const app = newTestApp()
    const res = await request(app).post('/forgot-password').send({ email: { $ne: null } })
    expect(res.status).toBe(400)
  })

  test('a non-string token to /reset-password/confirm does not crash the process', async () => {
    const app = newTestApp()
    const res = await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'alice@test.local', token: ['x'], new_password: 'newpass1' })
    expect(res.status).toBe(400)
  })

  test('a non-string password to /login does not crash the process', async () => {
    const app = newTestApp()
    const res = await request(app).post('/login').send({ email: 'alice@test.local', password: { a: 1 } })
    expect(res.status).toBe(401)
  })

  test('a non-string username/email to /register does not crash the process', async () => {
    const app = newTestApp()
    const res = await request(app).post('/register').send({ username: ['x'], email: 'a@b.local', password: 'p' })
    expect(res.status).toBe(400)
  })
})

describe('no other path can change a password', () => {
  test('there is no generic user-update endpoint', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app, 'alice@test.local')
    const res = await request(app)
      .post('/users/1')
      .set('Cookie', cookie)
      .send({ password: 'hacked' })
    expect(res.status).toBe(404)
  })

  test('PATCH on a project does not exist and cannot flip is_private', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app, 'alice@test.local')
    const res = await request(app)
      .patch('/projects/1')
      .set('Cookie', cookie)
      .send({ is_private: 0 })
    expect(res.status).toBe(404)

    // still 403 -- is_private was never flipped
    const stillPrivate = await request(app).get('/projects/1').set('Cookie', cookie)
    expect(stillPrivate.status).toBe(403)
  })
})

describe('score token handling', () => {
  test('a wrong score token is treated as not found, not forbidden', async () => {
    const app = newTestApp()
    const res = await request(app).get('/score/totally-wrong').set('Accept', 'application/json')
    expect(res.status).toBe(404)
  })
})
