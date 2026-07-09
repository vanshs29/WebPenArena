const request = require('supertest')
const { newTestApp, cleanup } = require('./helpers/testApp')

let app

beforeEach(() => { app = newTestApp() })
afterEach(() => cleanup(app))

test('GET / returns DocVault HTML', async () => {
  const res = await request(app).get('/')
  expect(res.status).toBe(200)
  expect(res.text).toContain('DocVault')
})

test('GET /files returns the file listing page', async () => {
  const res = await request(app).get('/files')
  expect(res.status).toBe(200)
  expect(res.text).toContain('readme.txt')
  expect(res.text).toContain('terms.txt')
  expect(res.text).toContain('faq.txt')
})

test('GET /about returns the about page', async () => {
  const res = await request(app).get('/about')
  expect(res.status).toBe(200)
  expect(res.text).toContain('DocVault')
})

test('GET /api/files returns the 3 seed filenames as JSON', async () => {
  const res = await request(app).get('/api/files')
  expect(res.status).toBe(200)
  expect(res.body).toHaveLength(3)
  expect(res.body).toEqual(expect.arrayContaining(['readme.txt', 'terms.txt', 'faq.txt']))
})

test('GET /files/view?name=readme.txt returns file content', async () => {
  const res = await request(app).get('/files/view?name=readme.txt')
  expect(res.status).toBe(200)
  expect(res.text).toContain('DocVault user guide.')
})

test('GET /files/view?name=terms.txt returns correct content', async () => {
  const res = await request(app).get('/files/view?name=terms.txt')
  expect(res.status).toBe(200)
  expect(res.text).toContain('Terms of service.')
})

test('GET /files/view without a name parameter returns 400', async () => {
  const res = await request(app).get('/files/view')
  expect(res.status).toBe(400)
})

test('GET /files/view?name=missing.txt returns 404', async () => {
  const res = await request(app).get('/files/view?name=missing.txt')
  expect(res.status).toBe(404)
})

test('unknown route returns 404', async () => {
  const res = await request(app).get('/nonexistent')
  expect(res.status).toBe(404)
})
