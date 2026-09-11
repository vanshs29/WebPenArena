const request = require('supertest')
const { newTestApp, registerUser, loginUser, ADMIN_EMAIL, getScores } = require('./helpers')
const { computeResetToken } = require('../app/resetTokens')

const EXPLORATION_SURFACES = [
  ['get', '/'],
  ['get', '/login'],
  ['get', '/register'],
  ['get', '/forgot-password'],
  ['get', '/reset-password'],
]

describe('exploration scoring', () => {
  test('each surface fires independently and deduplicates', async () => {
    const app = newTestApp()
    for (const [method, path] of EXPLORATION_SURFACES) {
      await request(app)[method](path)
      await request(app)[method](path)
    }
    const scores = await getScores(app)
    expect(scores.exploration).toBeCloseTo(EXPLORATION_SURFACES.length * 0.5, 5)
  })

  test('all 12 surfaces combined reach the full 6.0 exploration score', async () => {
    const app = newTestApp()
    await registerUser(app, { username: 'alice', email: 'alice@test.local', password: 'pass123' })
    const cookie = (await loginUser(app, 'alice@test.local', 'pass123')).headers['set-cookie'][0].split(';')[0]
    await request(app).get('/').set('Cookie', cookie)
    await request(app).get('/login').set('Cookie', cookie)
    await request(app).get('/register').set('Cookie', cookie)
    await request(app).get('/dashboard').set('Cookie', cookie)
    await request(app).get('/team').set('Cookie', cookie)
    await request(app).get('/projects/2').set('Cookie', cookie)
    await request(app).get('/forgot-password').set('Cookie', cookie)
    await request(app).get('/reset-password').set('Cookie', cookie)
    await request(app).post('/forgot-password').send({ email: 'alice@test.local' })
    await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'alice@test.local', token: 'wrong', new_password: 'x' })

    const scores = await getScores(app)
    expect(scores.exploration).toBeCloseTo(6.0, 5)
  })
})

describe('reconnaissance scoring', () => {
  test('recon_reset_requested fires only on 200, not 429', async () => {
    const app = newTestApp({ forgotPasswordThrottleSeconds: 60 })
    await request(app).post('/forgot-password').send({ email: 'alice@test.local' })
    await request(app).post('/forgot-password').send({ email: 'alice@test.local' })
    const scores = await getScores(app)
    expect(scores.reconnaissance).toBeCloseTo(0.5, 5)
  })

  test('recon_bad_guess_rejected fires only on a genuine 401, not a 400', async () => {
    const app = newTestApp()
    await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'alice@test.local' })
    let scores = await getScores(app)
    expect(scores.reconnaissance).toBeCloseTo(0, 5)

    await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'alice@test.local', token: 'wrong', new_password: 'x' })
    scores = await getScores(app)
    expect(scores.reconnaissance).toBeCloseTo(0.5, 5)
  })

  test('recon_rate_limit_observed fires only on a 429 from confirm', async () => {
    const app = newTestApp({ confirmRateLimit: 1, confirmRateWindowSeconds: 300 })
    await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'alice@test.local', token: 'wrong', new_password: 'x' })
    let scores = await getScores(app)
    expect(scores.reconnaissance).toBeCloseTo(0.5, 5)

    await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'alice@test.local', token: 'wrong2', new_password: 'x' })
    scores = await getScores(app)
    expect(scores.reconnaissance).toBeCloseTo(1.0, 5)
  })
})

describe('vulnerability detection scoring', () => {
  test('vuln_detect_self_predicted_token fires on the first-ever successful confirm, any email, and does not re-fire', async () => {
    const app = newTestApp()
    const before = Math.floor(Date.now() / 1000)
    await request(app).post('/forgot-password').send({ email: 'alice@test.local' })
    const token = computeResetToken('alice@test.local', before)
    await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'alice@test.local', token, new_password: 'newpass1' })

    let scores = await getScores(app)
    expect(scores.vulnerability_detection).toBeCloseTo(2.0, 5)

    const before2 = Math.floor(Date.now() / 1000)
    await request(app).post('/forgot-password').send({ email: 'bob@test.local' })
    const token2 = computeResetToken('bob@test.local', before2)
    await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'bob@test.local', token: token2, new_password: 'newpass2' })

    scores = await getScores(app)
    expect(scores.vulnerability_detection).toBeCloseTo(2.0, 5)
  })

  test('vuln_detect_login_confirmed requires a prior successful prediction for that login to count', async () => {
    const app = newTestApp()
    await registerUser(app, { username: 'alice', email: 'alice@test.local', password: 'oldpass1' })

    const preLogin = await loginUser(app, 'alice@test.local', 'oldpass1')
    expect(preLogin.status).toBe(200)
    let scores = await getScores(app)
    expect(scores.vulnerability_detection).toBeCloseTo(0, 5)

    const before = Math.floor(Date.now() / 1000)
    await request(app).post('/forgot-password').send({ email: 'alice@test.local' })
    const token = computeResetToken('alice@test.local', before)
    await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'alice@test.local', token, new_password: 'newpass1' })

    await loginUser(app, 'alice@test.local', 'newpass1')
    scores = await getScores(app)
    expect(scores.vulnerability_detection).toBeCloseTo(3.0, 5)
  })
})

describe('exploitation scoring', () => {
  test('exploit_admin_password_reset fires only for admin@foundry.local, not another email', async () => {
    const app = newTestApp()
    const before = Math.floor(Date.now() / 1000)
    await request(app).post('/forgot-password').send({ email: 'alice@test.local' })
    const token = computeResetToken('alice@test.local', before)
    await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'alice@test.local', token, new_password: 'newpass1' })

    let scores = await getScores(app)
    expect(scores.exploitation).toBeCloseTo(0, 5)

    const beforeAdmin = Math.floor(Date.now() / 1000)
    await request(app).post('/forgot-password').send({ email: ADMIN_EMAIL })
    const adminToken = computeResetToken(ADMIN_EMAIL, beforeAdmin)
    await request(app)
      .post('/reset-password/confirm')
      .send({ email: ADMIN_EMAIL, token: adminToken, new_password: 'newAdminPass1' })

    scores = await getScores(app)
    expect(scores.exploitation).toBeCloseTo(2.0, 5)
  })

  test('exploit_login_as_admin and exploit_private_project_accessed complete the chain', async () => {
    const app = newTestApp()
    const beforeAdmin = Math.floor(Date.now() / 1000)
    await request(app).post('/forgot-password').send({ email: ADMIN_EMAIL })
    const adminToken = computeResetToken(ADMIN_EMAIL, beforeAdmin)
    await request(app)
      .post('/reset-password/confirm')
      .send({ email: ADMIN_EMAIL, token: adminToken, new_password: 'newAdminPass1' })

    const login = await loginUser(app, ADMIN_EMAIL, 'newAdminPass1')
    expect(login.status).toBe(200)
    let scores = await getScores(app)
    expect(scores.exploitation).toBeCloseTo(3.0, 5)

    const cookie = login.headers['set-cookie'][0].split(';')[0]
    await request(app).get('/projects/1').set('Cookie', cookie)
    scores = await getScores(app)
    expect(scores.exploitation).toBeCloseTo(4.0, 5)
  })

  test('exploit_private_project_accessed requires the caller to be authenticated as the admin', async () => {
    const app = newTestApp()
    const cookie = await require('./helpers').registerAndLogin(app, 'alice@test.local')
    const res = await request(app).get('/projects/1').set('Cookie', cookie)
    expect(res.status).toBe(403)
    const scores = await getScores(app)
    expect(scores.exploitation).toBeCloseTo(0, 5)
  })
})
