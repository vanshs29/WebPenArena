const request = require('supertest')
const { newTestApp, registerUser } = require('./helpers')
const { computeResetToken } = require('../app/resetTokens')

describe('POST /reset-password/confirm', () => {
  test('the correctly-computed token succeeds and updates the password', async () => {
    const app = newTestApp()
    await registerUser(app, { username: 'alice', email: 'alice@test.local', password: 'oldpass1' })

    const before = Math.floor(Date.now() / 1000)
    await request(app).post('/forgot-password').send({ email: 'alice@test.local' })
    const token = computeResetToken('alice@test.local', before)

    const res = await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'alice@test.local', token, new_password: 'newpass1' })
    expect(res.status).toBe(200)

    const oldLogin = await request(app).post('/login').send({ email: 'alice@test.local', password: 'oldpass1' })
    expect(oldLogin.status).toBe(401)

    const newLogin = await request(app).post('/login').send({ email: 'alice@test.local', password: 'newpass1' })
    expect(newLogin.status).toBe(200)
  })

  test('a wrong token is rejected with 401', async () => {
    const app = newTestApp()
    await request(app).post('/forgot-password').send({ email: 'alice@test.local' })
    const res = await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'alice@test.local', token: 'deadbeef00', new_password: 'newpass1' })
    expect(res.status).toBe(401)
  })

  test('a token computed for a different email is rejected with 401', async () => {
    const app = newTestApp()
    const before = Math.floor(Date.now() / 1000)
    await request(app).post('/forgot-password').send({ email: 'alice@test.local' })
    const wrongToken = computeResetToken('bob@test.local', before)
    const res = await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'alice@test.local', token: wrongToken, new_password: 'newpass1' })
    expect(res.status).toBe(401)
  })

  test('an already-used request cannot be replayed', async () => {
    const app = newTestApp()
    const before = Math.floor(Date.now() / 1000)
    await request(app).post('/forgot-password').send({ email: 'alice@test.local' })
    const token = computeResetToken('alice@test.local', before)

    const first = await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'alice@test.local', token, new_password: 'newpass1' })
    expect(first.status).toBe(200)

    const replay = await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'alice@test.local', token, new_password: 'newpass2' })
    expect(replay.status).toBe(401)
  })

  test('a token for a request older than the expiry window is rejected with 401', async () => {
    const app = newTestApp({ pendingRequestExpirySeconds: 1 })
    const before = Math.floor(Date.now() / 1000)
    await request(app).post('/forgot-password').send({ email: 'alice@test.local' })
    const token = computeResetToken('alice@test.local', before)

    await new Promise((resolve) => setTimeout(resolve, 2200))

    const res = await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'alice@test.local', token, new_password: 'newpass1' })
    expect(res.status).toBe(401)
  })

  test('missing fields return 400', async () => {
    const app = newTestApp()
    const res = await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'alice@test.local' })
    expect(res.status).toBe(400)
  })

  test('no pending request for the email at all is rejected with 401, not a crash', async () => {
    const app = newTestApp()
    const res = await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'nobody-ever-requested@test.local', token: 'abc123', new_password: 'newpass1' })
    expect(res.status).toBe(401)
  })
})
