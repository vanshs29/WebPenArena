const request = require('supertest')
const { newTestApp, cleanup } = require('./helpers/testApp')

let app

beforeEach(() => { app = newTestApp() })
afterEach(() => cleanup(app))

test('traversal via ../secret.txt returns the flag', async () => {
  const res = await request(app).get('/files/view?name=../secret.txt')
  expect(res.status).toBe(200)
  expect(res.text).toContain('FLAG{traversal_docvault_easy}')
})

test('normal file is still served correctly alongside the vulnerability', async () => {
  const res = await request(app).get('/files/view?name=terms.txt')
  expect(res.status).toBe(200)
  expect(res.text).toContain('Terms of service.')
  expect(res.text).not.toContain('FLAG{')
})

test('GET /api/files never exposes the flag file', async () => {
  const res = await request(app).get('/api/files')
  expect(res.body).not.toContain('secret.txt')
})

test('deeper traversal (../../) also escapes the docs directory', async () => {
  const res = await request(app).get('/files/view?name=../../etc/hostname')
  expect(res.status).not.toBe(200)
})
