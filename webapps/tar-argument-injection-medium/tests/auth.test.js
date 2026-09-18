const request = require('supertest')
const { newTestApp, registerUser, loginUser, registerAndLogin, getCaseIdForEmail } = require('./helpers')

describe('registration and login', () => {
  test('registration creates a user and exactly one case', async () => {
    const app = newTestApp()
    const res = await registerUser(app, { email: 'bob@test.local', username: 'bob' })
    expect(res.status).toBe(201)

    const db = app.locals.db
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get('bob@test.local')
    expect(user).toBeTruthy()
    const cases = db.prepare('SELECT * FROM cases WHERE user_id = ?').all(user.id)
    expect(cases).toHaveLength(1)
    expect(cases[0].case_number).toMatch(/^ASH-\d{6}$/)
    expect(cases[0].last_compiled_at).toBeNull()
  })

  test('registration rejects a duplicate email', async () => {
    const app = newTestApp()
    await registerUser(app, { email: 'bob@test.local', username: 'bob' })
    const res = await registerUser(app, { email: 'bob@test.local', username: 'bob2' })
    expect(res.status).toBe(409)
  })

  test('login issues a session cookie for correct credentials', async () => {
    const app = newTestApp()
    await registerUser(app, { email: 'bob@test.local', username: 'bob', password: 'secretpw' })
    const res = await loginUser(app, 'bob@test.local', 'secretpw')
    expect(res.status).toBe(200)
    expect(res.headers['set-cookie'][0]).toMatch(/session=/)
  })

  test('login rejects wrong password', async () => {
    const app = newTestApp()
    await registerUser(app, { email: 'bob@test.local', username: 'bob', password: 'secretpw' })
    const res = await loginUser(app, 'bob@test.local', 'wrongpw')
    expect(res.status).toBe(401)
  })

  test('GET /case/:id requires ownership', async () => {
    const app = newTestApp()
    const cookieA = await registerAndLogin(app, 'alice@test.local')
    await registerAndLogin(app, 'carol@test.local')
    const carolCaseId = getCaseIdForEmail(app, 'carol@test.local')

    const res = await request(app).get(`/case/${carolCaseId}`).set('Cookie', cookieA)
    expect(res.status).toBe(403)
  })

  test('GET /case/:id renders the case detail for the owner', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app, 'alice@test.local')
    const caseId = getCaseIdForEmail(app, 'alice@test.local')

    const res = await request(app).get(`/case/${caseId}`).set('Cookie', cookie)
    expect(res.status).toBe(200)
    expect(res.text).toContain('ASH-')
  })

  test('GET /case/:id for a nonexistent case returns 404', async () => {
    const app = newTestApp()
    const cookie = await registerAndLogin(app, 'alice@test.local')
    const res = await request(app).get('/case/999').set('Cookie', cookie)
    expect(res.status).toBe(404)
  })
})
