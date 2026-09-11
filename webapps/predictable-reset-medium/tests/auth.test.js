const request = require('supertest')
const { newTestApp, registerUser, loginUser } = require('./helpers')

describe('registration', () => {
  test('registers a new member with a unique email and username', async () => {
    const app = newTestApp()
    const res = await registerUser(app, { username: 'bob', email: 'bob@test.local', password: 'secret123' })
    expect(res.status).toBe(201)
  })

  test('duplicate email is rejected with 409', async () => {
    const app = newTestApp()
    await registerUser(app, { username: 'bob', email: 'bob@test.local', password: 'secret123' })
    const res = await registerUser(app, { username: 'bob2', email: 'bob@test.local', password: 'secret123' })
    expect(res.status).toBe(409)
  })

  test('duplicate username is rejected with 409', async () => {
    const app = newTestApp()
    await registerUser(app, { username: 'bob', email: 'bob@test.local', password: 'secret123' })
    const res = await registerUser(app, { username: 'bob', email: 'bob2@test.local', password: 'secret123' })
    expect(res.status).toBe(409)
  })

  test('missing password is rejected with 400', async () => {
    const app = newTestApp()
    const res = await request(app).post('/register').send({ username: 'bob', email: 'bob@test.local' })
    expect(res.status).toBe(400)
  })

  test('registration always assigns the member role, ignoring a client-supplied role', async () => {
    const app = newTestApp()
    await request(app)
      .post('/register')
      .send({ username: 'bob', email: 'bob@test.local', password: 'secret123', role: 'admin' })

    const cookie = (await loginUser(app, 'bob@test.local', 'secret123')).headers['set-cookie'][0].split(';')[0]
    const teamRes = await request(app).get('/team').set('Cookie', cookie)
    expect(teamRes.status).toBe(200)
    // role must be 'member', not 'admin' -- checked via the team roster rendering
    expect(teamRes.text).toMatch(/<td>bob<\/td>\s*<td>member<\/td>/)
  })
})

describe('login', () => {
  test('valid credentials succeed and set a session cookie', async () => {
    const app = newTestApp()
    await registerUser(app, { username: 'bob', email: 'bob@test.local', password: 'secret123' })
    const res = await loginUser(app, 'bob@test.local', 'secret123')
    expect(res.status).toBe(200)
    expect(res.headers['set-cookie']).toBeDefined()
  })

  test('wrong password is rejected with 401', async () => {
    const app = newTestApp()
    await registerUser(app, { username: 'bob', email: 'bob@test.local', password: 'secret123' })
    const res = await loginUser(app, 'bob@test.local', 'wrongpass')
    expect(res.status).toBe(401)
  })

  test('unknown email is rejected with 401', async () => {
    const app = newTestApp()
    const res = await loginUser(app, 'nobody@test.local', 'secret123')
    expect(res.status).toBe(401)
  })

  test('email is treated case-insensitively', async () => {
    const app = newTestApp()
    await registerUser(app, { username: 'bob', email: 'Bob@Test.Local', password: 'secret123' })
    const res = await loginUser(app, 'bob@test.local', 'secret123')
    expect(res.status).toBe(200)
  })
})
