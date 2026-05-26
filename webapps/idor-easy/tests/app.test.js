const request = require('supertest')
const { createTestApp, cleanup } = require('./helpers')

let app

beforeEach(() => { app = createTestApp() })
afterEach(() => cleanup(app))

test('GET / returns 200', async () => {
  const res = await request(app).get('/')
  expect(res.status).toBe(200)
  expect(res.text).toContain('NoteNest')
})

test('GET /login returns 200', async () => {
  const res = await request(app).get('/login')
  expect(res.status).toBe(200)
})

test('GET /register returns 200', async () => {
  const res = await request(app).get('/register')
  expect(res.status).toBe(200)
})

test('unknown route returns 404', async () => {
  const res = await request(app).get('/doesnotexist')
  expect(res.status).toBe(404)
})

test('GET /notes without auth returns 401', async () => {
  const res = await request(app).get('/notes')
  expect(res.status).toBe(401)
})

test('GET /admin without auth returns 401', async () => {
  const res = await request(app).get('/admin')
  expect(res.status).toBe(401)
})
