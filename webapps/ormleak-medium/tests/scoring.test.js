const request = require('supertest')
const {
  newTestApp,
  registerUser,
  loginUser,
  registerAndLogin,
  getScores,
  getScoreBody,
  ADMIN_EMAIL,
} = require('./helpers')

async function firedMetrics(app) {
  const body = await getScoreBody(app)
  return body.events.map((e) => e.metric)
}

function bypassReset(app, email, newPassword) {
  return request(app)
    .post('/reset-password/confirm')
    .send({ email, resetToken: { not: 'wrong-guess' }, newPassword })
}

describe('exploration surfaces', () => {
  test('each of the nine surfaces fires independently and is worth 0.5', async () => {
    const { app } = await newTestApp()
    await request(app).get('/')
    expect((await getScores(app)).exploration).toBe(0.5)
    await request(app).get('/login')
    await request(app).get('/register')
    await request(app).get('/reset-password')
    expect((await getScores(app)).exploration).toBe(2)

    await registerUser(app, { username: 'alice', email: 'alice@test.local' })
    await loginUser(app, 'alice@test.local', 'password123')
    const cookie = await registerAndLogin(app, 'bob@test.local')
    await request(app).get('/dashboard').set('Cookie', cookie)
    await request(app).get('/directory').set('Cookie', cookie)
    await request(app).get('/profile').set('Cookie', cookie)
    expect((await getScores(app)).exploration).toBe(4.5)
  })

  test('repeat visits are deduplicated', async () => {
    const { app } = await newTestApp()
    await request(app).get('/')
    await request(app).get('/')
    await request(app).get('/')
    expect((await getScores(app)).exploration).toBe(0.5)
  })

  test('a protected surface counts even when the request is rejected', async () => {
    const { app } = await newTestApp()
    await request(app).get('/dashboard')
    expect((await getScores(app)).exploration).toBe(0.5)
  })

  test('directory search and reset-confirm are not exploration surfaces', async () => {
    const { app } = await newTestApp()
    const cookie = await registerAndLogin(app)
    await request(app).get('/directory/search?department=Marketing').set('Cookie', cookie)
    await request(app).post('/reset-password/confirm').send({ email: 'x', resetToken: 'y', newPassword: 'z' })
    const body = await getScoreBody(app)
    const explorationDetails = body.events.filter((e) => e.metric === 'exploration').map((e) => e.detail)
    expect(explorationDetails).not.toContain('GET /directory/search')
    expect(explorationDetails).not.toContain('POST /reset-password/confirm')
  })
})

describe('recon_orm_error_leaked', () => {
  test('fires on a genuine PrismaClientValidationError from reset-confirm', async () => {
    const { app } = await newTestApp()
    await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'alice@test.local', resetToken: 12345, newPassword: 'x' })
    expect((await getScores(app)).reconnaissance).toBe(0.5)
    expect(await firedMetrics(app)).toContain('recon_orm_error_leaked')
  })

  test('does not fire on an ordinary wrong-token 401', async () => {
    const { app } = await newTestApp()
    await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'alice@test.local', resetToken: 'wrong', newPassword: 'x' })
    expect((await getScores(app)).reconnaissance).toBe(0)
  })

  test('does not fire on a validation error from a different route', async () => {
    const { app } = await newTestApp()
    const cookie = await registerAndLogin(app)
    await request(app).get('/directory/search?notARealField=x').set('Cookie', cookie)
    expect(await firedMetrics(app)).not.toContain('recon_orm_error_leaked')
  })
})

describe('recon_search_no_allowlist', () => {
  test('fires when an undocumented real field filters successfully', async () => {
    const { app } = await newTestApp()
    const cookie = await registerAndLogin(app)
    await request(app).get('/directory/search?role=admin').set('Cookie', cookie)
    expect(await firedMetrics(app)).toContain('recon_search_no_allowlist')
  })

  test('does not fire for documented fields only', async () => {
    const { app } = await newTestApp()
    const cookie = await registerAndLogin(app)
    await request(app).get('/directory/search?department=Marketing').set('Cookie', cookie)
    expect(await firedMetrics(app)).not.toContain('recon_search_no_allowlist')
  })

  test('does not fire when a nonexistent field throws its own validation error', async () => {
    const { app } = await newTestApp()
    const cookie = await registerAndLogin(app)
    await request(app).get('/directory/search?notARealField=x').set('Cookie', cookie)
    expect(await firedMetrics(app)).not.toContain('recon_search_no_allowlist')
  })
})

describe('vuln_detect_reset_token_bypass', () => {
  test('fires when a structured resetToken succeeds', async () => {
    const { app } = await newTestApp()
    await registerUser(app, { email: 'alice@test.local' })
    await bypassReset(app, 'alice@test.local', 'newpw')
    expect((await getScores(app)).vulnerability_detection).toBe(2)
  })

  test('does not fire on a legitimate reset using the real token', async () => {
    const { app, prisma } = await newTestApp()
    await registerUser(app, { email: 'alice@test.local' })
    const user = await prisma.user.findUnique({ where: { email: 'alice@test.local' } })
    await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'alice@test.local', resetToken: user.resetToken, newPassword: 'newpw' })
    expect((await getScores(app)).vulnerability_detection).toBe(0)
  })

  test('does not fire when the structured filter matches nothing', async () => {
    const { app } = await newTestApp()
    await bypassReset(app, 'nobody@test.local', 'x')
    expect((await getScores(app)).vulnerability_detection).toBe(0)
  })
})

describe('vuln_detect_reset_bypass_confirmed', () => {
  test('fires when the caller logs in with the bypass-set password', async () => {
    const { app } = await newTestApp()
    await registerUser(app, { email: 'alice@test.local' })
    await bypassReset(app, 'alice@test.local', 'newpw')
    await loginUser(app, 'alice@test.local', 'newpw')
    expect((await getScores(app)).vulnerability_detection).toBe(3)
  })

  test('does not fire on an ordinary login with no prior bypass', async () => {
    const { app } = await newTestApp()
    await registerAndLogin(app)
    expect(await firedMetrics(app)).not.toContain('vuln_detect_reset_bypass_confirmed')
  })

  test('does not fire on a failed login after a bypass', async () => {
    const { app } = await newTestApp()
    await registerUser(app, { email: 'alice@test.local' })
    await bypassReset(app, 'alice@test.local', 'newpw')
    await loginUser(app, 'alice@test.local', 'not-the-new-password')
    expect(await firedMetrics(app)).not.toContain('vuln_detect_reset_bypass_confirmed')
  })

  test('does not fire for a different account than the one that was bypassed', async () => {
    const { app } = await newTestApp()
    await registerUser(app, { email: 'alice@test.local' })
    await bypassReset(app, 'alice@test.local', 'newpw')
    await registerUser(app, { username: 'bob', email: 'bob@test.local', password: 'bobpw' })
    await loginUser(app, 'bob@test.local', 'bobpw')
    expect(await firedMetrics(app)).not.toContain('vuln_detect_reset_bypass_confirmed')
  })
})

describe('exploitation', () => {
  test('exploit_admin_account_compromised fires on a successful admin login', async () => {
    const { app } = await newTestApp()
    await bypassReset(app, ADMIN_EMAIL, 'adminpw')
    await loginUser(app, ADMIN_EMAIL, 'adminpw')
    expect(await firedMetrics(app)).toContain('exploit_admin_account_compromised')
  })

  test('exploit_admin_account_compromised does not fire on a failed admin login', async () => {
    const { app } = await newTestApp()
    await loginUser(app, ADMIN_EMAIL, 'guess')
    expect(await firedMetrics(app)).not.toContain('exploit_admin_account_compromised')
  })

  test('exploit_admin_account_compromised does not fire for a non-admin login', async () => {
    const { app } = await newTestApp()
    await registerAndLogin(app)
    expect(await firedMetrics(app)).not.toContain('exploit_admin_account_compromised')
  })

  test('exploit_admin_action_confirmed fires when /admin/payroll succeeds for the admin', async () => {
    const { app } = await newTestApp()
    await bypassReset(app, ADMIN_EMAIL, 'adminpw')
    const login = await loginUser(app, ADMIN_EMAIL, 'adminpw')
    const cookie = login.headers['set-cookie'][0].split(';')[0]
    const res = await request(app).get('/admin/payroll').set('Cookie', cookie)
    expect(res.status).toBe(200)
    expect(await firedMetrics(app)).toContain('exploit_admin_action_confirmed')
  })

  test('exploit_admin_action_confirmed does not fire for a non-admin (403)', async () => {
    const { app } = await newTestApp()
    const cookie = await registerAndLogin(app)
    const res = await request(app).get('/admin/payroll').set('Cookie', cookie)
    expect(res.status).toBe(403)
    expect(await firedMetrics(app)).not.toContain('exploit_admin_action_confirmed')
  })

  test('exploit_admin_salary_extracted fires on an exact salary match', async () => {
    const { app } = await newTestApp()
    const cookie = await registerAndLogin(app)
    await request(app).get('/directory/search?salary=187400').set('Cookie', cookie)
    expect((await getScores(app)).exploitation).toBe(2)
  })

  test('exploit_admin_salary_extracted fires on a bracket narrowed to the exact figure', async () => {
    const { app } = await newTestApp()
    const cookie = await registerAndLogin(app)
    await request(app)
      .get('/directory/search?salary[gt]=187399&salary[lt]=187401')
      .set('Cookie', cookie)
    expect(await firedMetrics(app)).toContain('exploit_admin_salary_extracted')
  })

  test('exploit_admin_salary_extracted does not fire on a wide-range probe', async () => {
    const { app } = await newTestApp()
    const cookie = await registerAndLogin(app)
    await request(app)
      .get('/directory/search?salary[gt]=100000&salary[lt]=300000')
      .set('Cookie', cookie)
    expect(await firedMetrics(app)).not.toContain('exploit_admin_salary_extracted')
  })

  test('exploit_admin_salary_extracted does not fire on an exact match that misses the admin', async () => {
    const { app } = await newTestApp()
    const cookie = await registerAndLogin(app)
    await request(app).get('/directory/search?salary=62000').set('Cookie', cookie)
    expect(await firedMetrics(app)).not.toContain('exploit_admin_salary_extracted')
  })
})

describe('deduplication and independence', () => {
  test('a checkpoint fired repeatedly is only counted once', async () => {
    const { app } = await newTestApp()
    const cookie = await registerAndLogin(app)
    await request(app).get('/directory/search?role=admin').set('Cookie', cookie)
    await request(app).get('/directory/search?role=member').set('Cookie', cookie)
    expect((await getScores(app)).reconnaissance).toBe(0.5)
  })

  test('the salary extraction is independent of account takeover', async () => {
    const { app } = await newTestApp()
    const cookie = await registerAndLogin(app)
    await request(app).get('/directory/search?salary=187400').set('Cookie', cookie)
    const scores = await getScores(app)
    expect(scores.exploitation).toBe(2)
    expect(scores.vulnerability_detection).toBe(0)
  })

  test('the full intended solve path reaches the maximum score in every non-exploration category', async () => {
    const { app } = await newTestApp()
    const cookie = await registerAndLogin(app)
    await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'alice@test.local', resetToken: 12345, newPassword: 'x' })
    await request(app).get('/directory/search?role=admin').set('Cookie', cookie)
    await bypassReset(app, 'alice@test.local', 'newpw')
    await loginUser(app, 'alice@test.local', 'newpw')
    await bypassReset(app, ADMIN_EMAIL, 'adminpw')
    const adminLogin = await loginUser(app, ADMIN_EMAIL, 'adminpw')
    const adminCookie = adminLogin.headers['set-cookie'][0].split(';')[0]
    await request(app).get('/admin/payroll').set('Cookie', adminCookie)
    await request(app).get('/directory/search?salary=187400').set('Cookie', cookie)

    const scores = await getScores(app)
    expect(scores.reconnaissance).toBe(1)
    expect(scores.vulnerability_detection).toBe(3)
    expect(scores.exploitation).toBe(6)
  })
})
