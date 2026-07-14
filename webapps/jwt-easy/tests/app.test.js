const request = require('supertest')
const { newTestApp, makeHS256Token } = require('./helpers/testApp')

describe('GET /', () => {
  test('returns DevBlog HTML', async () => {
    const app = newTestApp()
    const res = await request(app).get('/')
    expect(res.status).toBe(200)
    expect(res.text).toContain('DevBlog')
  })
})

describe('POST /login', () => {
  test('valid credentials return a JWT and decoded payload', async () => {
    const app = newTestApp()
    const res = await request(app)
      .post('/login')
      .send({ email: 'alice@devblog.local', password: 'alice123' })
    expect(res.status).toBe(200)
    expect(res.body.token).toBeDefined()
    expect(res.body.payload.role).toBe('user')
  })

  test('wrong password returns 401', async () => {
    const app = newTestApp()
    const res = await request(app)
      .post('/login')
      .send({ email: 'alice@devblog.local', password: 'wrong' })
    expect(res.status).toBe(401)
  })

  test('unknown email returns 401', async () => {
    const app = newTestApp()
    const res = await request(app)
      .post('/login')
      .send({ email: 'nobody@devblog.local', password: 'whatever' })
    expect(res.status).toBe(401)
  })
})

describe('GET /posts', () => {
  test('returns the seeded posts as JSON', async () => {
    const app = newTestApp()
    const res = await request(app).get('/posts')
    expect(res.status).toBe(200)
    expect(res.body.length).toBe(3)
  })
})

describe('POST /posts', () => {
  test('requires authentication', async () => {
    const app = newTestApp()
    const res = await request(app).post('/posts').send({ title: 'x', body: 'y' })
    expect(res.status).toBe(401)
  })

  test('authenticated user can create a post', async () => {
    const app = newTestApp()
    const token = makeHS256Token({ sub: '1', role: 'user' })
    const res = await request(app)
      .post('/posts')
      .set('Authorization', `Bearer ${token}`)
      .send({ title: 'New post', body: 'Post body' })
    expect(res.status).toBe(201)
    expect(res.body.title).toBe('New post')
  })
})

describe('GET /admin', () => {
  test('returns 401 without a token', async () => {
    const app = newTestApp()
    const res = await request(app).get('/admin')
    expect(res.status).toBe(401)
  })

  test('returns 401 with a valid user-role HS256 token', async () => {
    const app = newTestApp()
    const token = makeHS256Token({ sub: '1', role: 'user' })
    const res = await request(app).get('/admin').set('Authorization', `Bearer ${token}`)
    expect(res.status).toBe(401)
  })
})
