const request = require('supertest')
const { newTestApp, registerUser, loginUser, ADMIN_EMAIL } = require('./helpers')

describe('registration and login', () => {
  test('registration creates a member with a non-empty resetToken', async () => {
    const { app, prisma } = await newTestApp()
    const res = await registerUser(app, { username: 'carol', email: 'carol@test.local' })
    expect(res.status).toBe(201)

    const user = await prisma.user.findUnique({ where: { email: 'carol@test.local' } })
    expect(user.role).toBe('member')
    expect(typeof user.resetToken).toBe('string')
    expect(user.resetToken.length).toBeGreaterThan(0)
  })

  test('duplicate email is rejected', async () => {
    const { app } = await newTestApp()
    await registerUser(app, { email: 'dup@test.local' })
    const res = await registerUser(app, { username: 'someoneelse', email: 'dup@test.local' })
    expect(res.status).toBe(409)
  })

  test('duplicate username is rejected', async () => {
    const { app } = await newTestApp()
    await registerUser(app, { username: 'dupname', email: 'first@test.local' })
    const res = await registerUser(app, { username: 'dupname', email: 'second@test.local' })
    expect(res.status).toBe(409)
  })

  test('missing fields are rejected', async () => {
    const { app } = await newTestApp()
    const res = await request(app).post('/register').send({ username: 'incomplete' })
    expect(res.status).toBe(400)
  })

  test('login with valid credentials succeeds and sets a session cookie', async () => {
    const { app } = await newTestApp()
    await registerUser(app, { email: 'dana@test.local', password: 'pw123' })
    const res = await loginUser(app, 'dana@test.local', 'pw123')
    expect(res.status).toBe(200)
    expect(res.headers['set-cookie'][0]).toMatch(/^session=/)
  })

  test('login with the wrong password is rejected', async () => {
    const { app } = await newTestApp()
    await registerUser(app, { email: 'erin@test.local', password: 'pw123' })
    const res = await loginUser(app, 'erin@test.local', 'wrongpw')
    expect(res.status).toBe(401)
  })

  test('login for an unknown email is rejected', async () => {
    const { app } = await newTestApp()
    const res = await loginUser(app, 'nobody@test.local', 'whatever')
    expect(res.status).toBe(401)
  })

  test('the seeded admin account exists and is not a member', async () => {
    const { prisma } = await newTestApp()
    const admin = await prisma.user.findUnique({ where: { email: ADMIN_EMAIL } })
    expect(admin).not.toBeNull()
    expect(admin.role).toBe('admin')
  })
})
