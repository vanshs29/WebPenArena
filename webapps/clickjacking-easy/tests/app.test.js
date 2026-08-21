const request = require('supertest')
const { createTestApp, cleanup, registerAndLogin } = require('./helpers/testApp')

let app

beforeEach(() => { app = createTestApp() })
afterEach(() => cleanup(app))

test('GET / returns 200', async () => {
  const res = await request(app).get('/')
  expect(res.status).toBe(200)
  expect(res.text).toContain('BillFold')
})

test('GET /register returns 200', async () => {
  const res = await request(app).get('/register')
  expect(res.status).toBe(200)
})

test('GET /login returns 200', async () => {
  const res = await request(app).get('/login')
  expect(res.status).toBe(200)
})

test('GET /about returns 200 and documents the review bot behaviour', async () => {
  const res = await request(app).get('/about')
  expect(res.status).toBe(200)
  expect(res.text).toContain('1280')
  expect(res.text).toContain('800')
  expect(res.text).toContain('640, 400')
  expect(res.text).toContain('640, 450')
})

test('unknown route returns 404', async () => {
  const res = await request(app).get('/doesnotexist')
  expect(res.status).toBe(404)
})

test('POST /register creates an account and issues a token', async () => {
  const token = await registerAndLogin(app, 'newuser@example.com', 'pw12345')
  expect(typeof token).toBe('string')
})

test('POST /register rejects a duplicate email', async () => {
  await registerAndLogin(app, 'dupe@example.com', 'pw12345')
  const res = await request(app)
    .post('/register')
    .set('Content-Type', 'application/json')
    .send({ email: 'dupe@example.com', password: 'pw12345' })
  expect(res.status).toBe(409)
})

test('POST /login rejects wrong password', async () => {
  await registerAndLogin(app, 'wrongpw@example.com', 'pw12345')
  const res = await request(app)
    .post('/login')
    .set('Content-Type', 'application/json')
    .send({ email: 'wrongpw@example.com', password: 'incorrect' })
  expect(res.status).toBe(401)
})

test('GET /account/deactivate without auth returns 401', async () => {
  const res = await request(app).get('/account/deactivate')
  expect(res.status).toBe(401)
})

test('GET /pages/new without auth returns 401', async () => {
  const res = await request(app).get('/pages/new')
  expect(res.status).toBe(401)
})

test('GET /report without auth returns 401', async () => {
  const res = await request(app).get('/report')
  expect(res.status).toBe(401)
})

test('authenticated GET /account/deactivate returns 200 and shows an active status', async () => {
  const token = await registerAndLogin(app, 'view@example.com', 'pw12345')
  const res = await request(app).get('/account/deactivate').set('Authorization', `Bearer ${token}`)
  expect(res.status).toBe(200)
  expect(res.text).toContain('Status: Active')
})

test('authenticated POST /account/deactivate flips the caller\'s own subscription off', async () => {
  const token = await registerAndLogin(app, 'self@example.com', 'pw12345')
  const res = await request(app).post('/account/deactivate').set('Authorization', `Bearer ${token}`)
  expect(res.status).toBe(200)

  const after = await request(app).get('/account/deactivate').set('Authorization', `Bearer ${token}`)
  expect(after.text).toContain('Status: Inactive')
})

test('POST /pages stores submitted HTML and strips <script>', async () => {
  const token = await registerAndLogin(app, 'author@example.com', 'pw12345')
  const res = await request(app)
    .post('/pages')
    .set('Authorization', `Bearer ${token}`)
    .set('Content-Type', 'application/json')
    .send({ html: '<p>hi</p><script>alert(1)</script>' })
  expect(res.status).toBe(201)
  const viewRes = await request(app).get(`/pages/${res.body.id}`)
  expect(viewRes.status).toBe(200)
  expect(viewRes.text).toContain('hi')
  expect(viewRes.text).not.toMatch(/<script/i)
})

test('GET /pages/:id is publicly viewable without auth', async () => {
  const token = await registerAndLogin(app, 'pub@example.com', 'pw12345')
  const created = await request(app)
    .post('/pages')
    .set('Authorization', `Bearer ${token}`)
    .set('Content-Type', 'application/json')
    .send({ html: '<p>public page</p>' })
  const res = await request(app).get(`/pages/${created.body.id}`)
  expect(res.status).toBe(200)
  expect(res.text).toContain('public page')
})

test('GET /pages/:id returns 404 for an unknown id', async () => {
  const res = await request(app).get('/pages/999999')
  expect(res.status).toBe(404)
})

test('POST /report stores a reviewable URL', async () => {
  const token = await registerAndLogin(app, 'reporter@example.com', 'pw12345')
  const res = await request(app)
    .post('/report')
    .set('Authorization', `Bearer ${token}`)
    .set('Content-Type', 'application/json')
    .send({ url: '/pages/1' })
  expect(res.status).toBe(201)
})
