const request = require('supertest')
const {
  newTestApp,
  registerUser,
  loginUser,
  registerAndLogin,
  loginAsPlatformAdmin,
} = require('./helpers')

describe('registration and login', () => {
  test('GET / renders the landing page', async () => {
    const app = newTestApp()
    const res = await request(app).get('/')
    expect(res.status).toBe(200)
    expect(res.text).toContain('Thornfield')
  })

  test('registering a new workspace name creates the workspace and grants admin', async () => {
    const app = newTestApp()
    const res = await registerUser(app, { workspaceName: 'Acme Corp', email: 'first@acme.example' })
    expect(res.status).toBe(201)
    expect(res.body.role).toBe('admin')
  })

  test('registering into an existing workspace name joins as an ordinary member', async () => {
    const app = newTestApp()
    await registerUser(app, { workspaceName: 'Acme Corp', email: 'first@acme.example' })
    const res = await registerUser(app, { workspaceName: 'Acme Corp', email: 'second@acme.example' })
    expect(res.status).toBe(201)
    expect(res.body.role).toBe('member')
  })

  test('registering with an already-used email is rejected', async () => {
    const app = newTestApp()
    await registerUser(app, { workspaceName: 'Acme Corp', email: 'first@acme.example' })
    const res = await registerUser(app, { workspaceName: 'Other Co', email: 'first@acme.example' })
    expect(res.status).toBe(409)
  })

  test('login sets a session cookie for a valid user', async () => {
    const app = newTestApp()
    await registerUser(app, { workspaceName: 'Acme Corp', email: 'first@acme.example' })
    const res = await loginUser(app, 'first@acme.example')
    expect(res.status).toBe(200)
    expect(res.headers['set-cookie']).toBeDefined()
  })

  test('login with a wrong password is rejected', async () => {
    const app = newTestApp()
    await registerUser(app, { workspaceName: 'Acme Corp', email: 'first@acme.example' })
    const res = await loginUser(app, 'first@acme.example', 'wrong-password')
    expect(res.status).toBe(401)
  })

  test('a valid session cookie can reach the dashboard', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app, { workspaceName: 'Acme Corp', email: 'first@acme.example' })
    const res = await request(app).get('/dashboard').set('Cookie', cookie)
    expect(res.status).toBe(200)
  })

  test('the dashboard requires auth', async () => {
    const app = newTestApp()
    const res = await request(app).get('/dashboard')
    expect(res.status).toBe(401)
  })

  test('the seeded platform admin can log in through the ordinary login route', async () => {
    const app = newTestApp()
    const cookie = await loginAsPlatformAdmin(app)
    expect(cookie).toBeDefined()
  })
})
