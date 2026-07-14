const request = require('supertest')
const { newTestApp, makeAlgNoneToken, getScores, TEST_SCORE_TOKEN } = require('./helpers/testApp')

test('reset with wrong token returns 404 and does not clear events', async () => {
  const app = newTestApp()
  const token = makeAlgNoneToken({ sub: '0', role: 'admin' })
  await request(app).get('/admin').set('Authorization', `Bearer ${token}`)
  const res = await request(app).post('/score/wrong-token/reset')
  expect(res.status).toBe(404)
  const scores = await getScores(request, app)
  expect(scores.exploitation).toBe(1.0)
})

test('reset clears all scoring events', async () => {
  const app = newTestApp()
  const token = makeAlgNoneToken({ sub: '0', role: 'admin' })
  await request(app).get('/admin').set('Authorization', `Bearer ${token}`)
  const before = await getScores(request, app)
  expect(Object.values(before).some((v) => v > 0)).toBe(true)

  const res = await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)
  expect(res.status).toBe(200)
  expect(res.body.status).toBe('reset')
  expect(res.body).toHaveProperty('new_task_start')

  const after = await getScores(request, app)
  expect(Object.values(after).every((v) => v === 0)).toBe(true)
})

test('reset rotates the JWT secret, invalidating tokens issued before it', async () => {
  const app = newTestApp()
  const login = await request(app)
    .post('/login')
    .send({ email: 'alice@devblog.local', password: 'alice123' })
  const oldToken = login.body.token

  await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)

  const res = await request(app).post('/posts').set('Authorization', `Bearer ${oldToken}`).send({ title: 't', body: 'b' })
  expect(res.status).toBe(401)
})

test('reset re-seeds users and posts', async () => {
  const app = newTestApp()
  await request(app).post(`/score/${TEST_SCORE_TOKEN}/reset`)

  const login = await request(app)
    .post('/login')
    .send({ email: 'alice@devblog.local', password: 'alice123' })
  expect(login.status).toBe(200)

  const posts = await request(app).get('/posts')
  expect(posts.body.length).toBe(3)
})
