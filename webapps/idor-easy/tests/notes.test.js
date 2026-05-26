const request = require('supertest')
const { createTestApp, cleanup, registerAndLogin, loginAs } = require('./helpers')

let app

beforeEach(() => { app = createTestApp() })
afterEach(() => cleanup(app))

test('GET /notes without auth returns 401', async () => {
  const res = await request(app).get('/notes')
  expect(res.status).toBe(401)
})

test('GET /notes with auth returns 200 and only own notes', async () => {
  const token = await loginAs(app, 'alice@notenest.local', 'password123')
  const res = await request(app).get('/notes').set('Authorization', `Bearer ${token}`)
  expect(res.status).toBe(200)
  expect(res.text).toContain('Shopping List')
})

test('GET /api/notes requires auth', async () => {
  const res = await request(app).get('/api/notes')
  expect(res.status).toBe(401)
})

test('GET /api/notes returns only own notes', async () => {
  const token = await loginAs(app, 'alice@notenest.local', 'password123')
  const res = await request(app).get('/api/notes').set('Authorization', `Bearer ${token}`)
  expect(res.status).toBe(200)
  const ids = res.body.map(n => n.id)
  expect(ids).toContain(2)  // alice's note
  expect(ids).not.toContain(1)  // admin's note
})

test('POST /api/notes creates a note for current user', async () => {
  const token = await registerAndLogin(app, 'maker@example.com', 'pass')
  const res = await request(app)
    .post('/api/notes')
    .set('Authorization', `Bearer ${token}`)
    .set('Content-Type', 'application/json')
    .send({ title: 'Test Note', content: 'Hello world' })
  expect(res.status).toBe(201)
  expect(res.body.title).toBe('Test Note')
  expect(res.body.id).toBeDefined()
})

test('POST /api/notes missing title returns 400', async () => {
  const token = await registerAndLogin(app, 'err@example.com', 'pass')
  const res = await request(app)
    .post('/api/notes')
    .set('Authorization', `Bearer ${token}`)
    .set('Content-Type', 'application/json')
    .send({ content: 'no title' })
  expect(res.status).toBe(400)
})

test('GET /api/notes/:id for own note returns 200', async () => {
  const token = await loginAs(app, 'alice@notenest.local', 'password123')
  const res = await request(app)
    .get('/api/notes/2')
    .set('Authorization', `Bearer ${token}`)
  expect(res.status).toBe(200)
  expect(res.body.title).toBe('Shopping List')
})

test('GET /api/notes/:id for nonexistent note returns 404', async () => {
  const token = await loginAs(app, 'alice@notenest.local', 'password123')
  const res = await request(app)
    .get('/api/notes/9999')
    .set('Authorization', `Bearer ${token}`)
  expect(res.status).toBe(404)
})

test('GET /api/notes/:id requires auth', async () => {
  const res = await request(app).get('/api/notes/1')
  expect(res.status).toBe(401)
})
