const request = require('supertest')
const { createTestApp, cleanup, registerAndLogin, loginAs } = require('./helpers')

let app

beforeEach(() => { app = createTestApp() })
afterEach(() => cleanup(app))

test('POST /register creates user and returns token', async () => {
  const res = await request(app)
    .post('/register')
    .set('Content-Type', 'application/json')
    .send({ email: 'new@example.com', password: 'pass123' })
  expect(res.status).toBe(201)
  expect(res.body.token).toBeDefined()
})

test('POST /register duplicate email returns 409', async () => {
  await request(app)
    .post('/register')
    .set('Content-Type', 'application/json')
    .send({ email: 'dup@example.com', password: 'pass' })
  const res = await request(app)
    .post('/register')
    .set('Content-Type', 'application/json')
    .send({ email: 'dup@example.com', password: 'pass' })
  expect(res.status).toBe(409)
})

test('POST /register missing fields returns 400', async () => {
  const res = await request(app)
    .post('/register')
    .set('Content-Type', 'application/json')
    .send({ email: 'x@x.com' })
  expect(res.status).toBe(400)
})

test('POST /register cannot set role to admin', async () => {
  const regRes = await request(app)
    .post('/register')
    .set('Content-Type', 'application/json')
    .send({ email: 'hacker@example.com', password: 'pass', role: 'admin' })
  expect(regRes.status).toBe(201)
  // Use the token to access /admin — should be 403
  const res = await request(app)
    .get('/admin')
    .set('Authorization', `Bearer ${regRes.body.token}`)
  expect(res.status).toBe(403)
})

test('POST /login JSON returns token for valid credentials', async () => {
  const res = await request(app)
    .post('/login')
    .set('Content-Type', 'application/json')
    .send({ email: 'alice@notenest.local', password: 'password123' })
  expect(res.status).toBe(200)
  expect(res.body.token).toBeDefined()
})

test('POST /login wrong password returns 401', async () => {
  const res = await request(app)
    .post('/login')
    .set('Content-Type', 'application/json')
    .send({ email: 'alice@notenest.local', password: 'wrong' })
  expect(res.status).toBe(401)
})

test('POST /login unknown email returns 401', async () => {
  const res = await request(app)
    .post('/login')
    .set('Content-Type', 'application/json')
    .send({ email: 'nobody@example.com', password: 'anything' })
  expect(res.status).toBe(401)
})

test('POST /login form sets cookie and redirects to /notes', async () => {
  const res = await request(app)
    .post('/login')
    .set('Content-Type', 'application/x-www-form-urlencoded')
    .send('email=alice@notenest.local&password=password123')
  expect(res.status).toBe(302)
  expect(res.headers.location).toBe('/notes')
  expect(res.headers['set-cookie']).toBeDefined()
  expect(res.headers['set-cookie'][0]).toMatch(/token=/)
})

test('GET /logout clears cookie and redirects', async () => {
  const token = await loginAs(app, 'alice@notenest.local', 'password123')
  const res = await request(app).get('/logout').set('Cookie', `token=${token}`)
  expect(res.status).toBe(302)
  expect(res.headers['set-cookie'][0]).toMatch(/token=;/)
})

test('invalid JWT token returns 401 on protected route', async () => {
  const res = await request(app)
    .get('/api/notes')
    .set('Authorization', 'Bearer invalid.token.value')
  expect(res.status).toBe(401)
})
