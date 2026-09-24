const request = require('supertest')
const { newTestApp, registerAndLogin } = require('./helpers')

describe('static pages', () => {
  test('home page renders', async () => {
    const app = await newTestApp()
    const res = await request(app).get('/')
    expect(res.status).toBe(200)
    expect(res.text).toContain('Meridian')
  })

  test('login page renders', async () => {
    const app = await newTestApp()
    const res = await request(app).get('/login')
    expect(res.status).toBe(200)
  })

  test('register page renders', async () => {
    const app = await newTestApp()
    const res = await request(app).get('/register')
    expect(res.status).toBe(200)
  })
})

describe('registration', () => {
  test('creates a new organization and its first member as org_admin', async () => {
    const app = await newTestApp()
    const res = await request(app)
      .post('/register')
      .send({ orgName: 'Test Registrar Co', name: 'Bob Test', email: 'bob@test.local', password: 'pw123456' })
    expect(res.status).toBe(201)
    expect(res.body.member.role).toBe('org_admin')

    const pool = app.locals.pool
    const { rows: orgRows } = await pool.query('SELECT * FROM organizations WHERE name = $1', [
      'Test Registrar Co',
    ])
    expect(orgRows).toHaveLength(1)

    const { rows: memberRows } = await pool.query('SELECT * FROM members WHERE email = $1', [
      'bob@test.local',
    ])
    expect(memberRows).toHaveLength(1)
    expect(memberRows[0].org_id).toBe(orgRows[0].id)
    expect(memberRows[0].role).toBe('org_admin')
  })

  test('rejects a duplicate email with 409', async () => {
    const app = await newTestApp()
    await request(app)
      .post('/register')
      .send({ orgName: 'Org A', name: 'Bob', email: 'dupe@test.local', password: 'pw123456' })
    const res = await request(app)
      .post('/register')
      .send({ orgName: 'Org B', name: 'Bob2', email: 'dupe@test.local', password: 'other' })
    expect(res.status).toBe(409)
  })

  test('rejects a missing password with 400', async () => {
    const app = await newTestApp()
    const res = await request(app)
      .post('/register')
      .send({ orgName: 'Org C', name: 'Bob', email: 'nopass@test.local' })
    expect(res.status).toBe(400)
  })
})

describe('login', () => {
  test('valid credentials succeed and set a session cookie', async () => {
    const app = await newTestApp()
    await request(app)
      .post('/register')
      .send({ orgName: 'Login Org', name: 'Carol', email: 'carol@test.local', password: 'pw123456' })
    const res = await request(app)
      .post('/login')
      .send({ email: 'carol@test.local', password: 'pw123456' })
    expect(res.status).toBe(200)
    expect(res.headers['set-cookie'][0]).toMatch(/^session=/)
  })

  test('wrong password returns 401', async () => {
    const app = await newTestApp()
    await request(app)
      .post('/register')
      .send({ orgName: 'Login Org 2', name: 'Dave', email: 'dave@test.local', password: 'pw123456' })
    const res = await request(app)
      .post('/login')
      .send({ email: 'dave@test.local', password: 'wrongpassword' })
    expect(res.status).toBe(401)
  })

  test('unknown email returns 401', async () => {
    const app = await newTestApp()
    const res = await request(app)
      .post('/login')
      .send({ email: 'nobody@test.local', password: 'whatever' })
    expect(res.status).toBe(401)
  })
})

describe('registerAndLogin helper sanity', () => {
  test('produces a usable session cookie', async () => {
    const app = await newTestApp()
    const { cookie } = await registerAndLogin(app)
    const res = await request(app).get('/dashboard').set('Cookie', cookie)
    expect(res.status).toBe(200)
  })
})
