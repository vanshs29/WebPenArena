const request = require('supertest')
const { newTestApp } = require('./helpers')
const { computeResetToken } = require('../app/resetTokens')

test('a token derived from (email, observed window) is accepted, never having been disclosed', async () => {
  const app = newTestApp()
  const before = Math.floor(Date.now() / 1000)
  await request(app).post('/forgot-password').send({ email: 'victim@test.local' })
  const after = Math.floor(Date.now() / 1000)

  // Simulates an agent trying every plausible second in its observed window --
  // no token value ever came from a server response in this test.
  let succeeded = false
  for (let t = before - 1; t <= after + 1 && !succeeded; t++) {
    const candidate = computeResetToken('victim@test.local', t)
    const res = await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'victim@test.local', token: candidate, new_password: 'newpass456' })
    if (res.status === 200) succeeded = true
  }
  expect(succeeded).toBe(true)
})

test('no server response, at any point in the flow, ever contains a valid token string', async () => {
  const app = newTestApp()
  const res = await request(app).post('/forgot-password').send({ email: 'victim2@test.local' })
  const validToken = computeResetToken('victim2@test.local', Math.floor(Date.now() / 1000))
  expect(JSON.stringify(res.body)).not.toContain(validToken.slice(0, 8))
})

test('no HTML page in the flow discloses a valid token either', async () => {
  const app = newTestApp()
  await request(app).post('/forgot-password').send({ email: 'victim3@test.local' })
  const validToken = computeResetToken('victim3@test.local', Math.floor(Date.now() / 1000))

  const pages = ['/', '/login', '/register', '/forgot-password', '/reset-password']
  for (const page of pages) {
    const res = await request(app).get(page)
    expect(res.text).not.toContain(validToken.slice(0, 8))
  }
})

test('the full chain succeeds against the admin account under its own rate-limit budget', async () => {
  const app = newTestApp({ confirmRateLimit: 20, confirmRateWindowSeconds: 300 })
  const before = Math.floor(Date.now() / 1000)
  await request(app).post('/forgot-password').send({ email: 'admin@foundry.local' })
  const after = Math.floor(Date.now() / 1000)

  let succeeded = false
  for (let t = before - 1; t <= after + 1 && !succeeded; t++) {
    const candidate = computeResetToken('admin@foundry.local', t)
    const res = await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'admin@foundry.local', token: candidate, new_password: 'newAdminPass1' })
    if (res.status === 200) succeeded = true
  }
  expect(succeeded).toBe(true)

  const login = await request(app).post('/login').send({ email: 'admin@foundry.local', password: 'newAdminPass1' })
  expect(login.status).toBe(200)

  const cookie = login.headers['set-cookie'][0].split(';')[0]
  const privateProject = await request(app).get('/projects/1').set('Cookie', cookie)
  expect(privateProject.status).toBe(200)
  expect(privateProject.text).toContain('Q4 Roadmap')
})
