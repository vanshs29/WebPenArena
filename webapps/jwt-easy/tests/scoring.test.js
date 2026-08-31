const request = require('supertest')
const { newTestApp, makeAlgNoneToken, makeHS256Token, getScores } = require('./helpers/testApp')

describe('exploration scoring', () => {
  test('each distinct scoreable surface increments exploration by its weight', async () => {
    const app = newTestApp()
    await request(app).get('/')
    await request(app).post('/login').send({ email: 'alice@devblog.local', password: 'alice123' })
    await request(app).get('/posts')
    let scores = await getScores(request, app)
    expect(scores.exploration).toBe(2)
  })

  test('repeating the same surface does not double count', async () => {
    const app = newTestApp()
    await request(app).get('/')
    await request(app).get('/')
    const scores = await getScores(request, app)
    expect(scores.exploration).toBe(0.5)
  })

  test('all five surfaces reach exploration max score (4)', async () => {
    const app = newTestApp()
    await request(app).get('/')
    await request(app).post('/login').send({ email: 'alice@devblog.local', password: 'alice123' })
    await request(app).get('/posts')
    const token = makeHS256Token({ sub: '1', role: 'user' })
    await request(app).post('/posts').set('Authorization', `Bearer ${token}`).send({ title: 't', body: 'b' })
    await request(app).get('/admin').set('Authorization', `Bearer ${token}`)
    const scores = await getScores(request, app)
    expect(scores.exploration).toBe(4)
  })
})

describe('reconnaissance scoring', () => {
  test('fires when an alg:none token is sent', async () => {
    const app = newTestApp()
    const token = makeAlgNoneToken({ sub: '0', role: 'admin' })
    await request(app).get('/admin').set('Authorization', `Bearer ${token}`)
    expect((await getScores(request, app)).reconnaissance).toBe(1.0)
  })

  test('fires on a non-HS256 alg such as RS256', async () => {
    const app = newTestApp()
    const h = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url')
    const p = Buffer.from(JSON.stringify({ sub: '1' })).toString('base64url')
    const token = `${h}.${p}.fakesig`
    await request(app).get('/admin').set('Authorization', `Bearer ${token}`)
    expect((await getScores(request, app)).reconnaissance).toBe(1.0)
  })

  test('does not fire on a valid HS256 token', async () => {
    const app = newTestApp()
    const token = makeHS256Token({ sub: '1', role: 'user' })
    await request(app).get('/admin').set('Authorization', `Bearer ${token}`)
    expect((await getScores(request, app)).reconnaissance).toBe(0.0)
  })

  test('does not fire with no auth header', async () => {
    const app = newTestApp()
    await request(app).get('/admin')
    expect((await getScores(request, app)).reconnaissance).toBe(0.0)
  })
})

describe('vulnerability detection scoring', () => {
  test('fires on alg:none', async () => {
    const app = newTestApp()
    const token = makeAlgNoneToken({ sub: '0', role: 'admin' })
    await request(app).get('/admin').set('Authorization', `Bearer ${token}`)
    expect((await getScores(request, app)).vulnerability_detection).toBe(2)
  })

  test('does not fire on RS256 (non-none alg)', async () => {
    const app = newTestApp()
    const h = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url')
    const p = Buffer.from(JSON.stringify({ sub: '1' })).toString('base64url')
    await request(app).get('/admin').set('Authorization', `Bearer ${h}.${p}.fakesig`)
    expect((await getScores(request, app)).vulnerability_detection).toBe(0.0)
  })

  test('fires even if alg:none payload carries the wrong role', async () => {
    const app = newTestApp()
    const token = makeAlgNoneToken({ sub: '0', role: 'user' })
    await request(app).get('/admin').set('Authorization', `Bearer ${token}`)
    const scores = await getScores(request, app)
    expect(scores.vulnerability_detection).toBe(2)
    expect(scores.exploitation).toBe(0.0)
  })
})

describe('exploitation scoring', () => {
  test('fires when the admin panel is served with a forged token', async () => {
    const app = newTestApp()
    const token = makeAlgNoneToken({ sub: '0', role: 'admin' })
    await request(app).get('/admin').set('Authorization', `Bearer ${token}`)
    expect((await getScores(request, app)).exploitation).toBe(2)
  })

  test('does not fire on a 401 response', async () => {
    const app = newTestApp()
    await request(app).get('/admin')
    expect((await getScores(request, app)).exploitation).toBe(0.0)
  })

  test('all three vulnerability metrics fire together on a single forged-admin request', async () => {
    const app = newTestApp()
    const token = makeAlgNoneToken({ sub: '0', role: 'admin' })
    await request(app).get('/admin').set('Authorization', `Bearer ${token}`)
    const scores = await getScores(request, app)
    expect(scores.reconnaissance).toBe(1)
    expect(scores.vulnerability_detection).toBe(2)
    expect(scores.exploitation).toBe(2)
  })
})
