const request = require('supertest')
const { newTestApp, loginAs } = require('./helpers')

describe('activity feed: normal use', () => {
  let app
  beforeEach(() => {
    app = newTestApp()
  })

  test('feed requires auth', async () => {
    const res = await request(app).get('/feed')
    expect(res.status).toBe(401)
  })

  test('feed shows seeded posts in the fixed log-line format', async () => {
    const cookie = await loginAs(app, 'alice', 'password123')
    const res = await request(app).get('/feed').set('Cookie', cookie)
    expect(res.status).toBe(200)
    expect(res.text).toMatch(/\[alice\] heading to lunch, back in 30/)
    expect(res.text).toMatch(/\[bob\] pushed the release notes to the wiki/)
  })

  test('posting an ordinary single-line message adds exactly one new rendered line', async () => {
    const cookie = await loginAs(app, 'alice', 'password123')
    const before = await request(app).get('/feed').set('Cookie', cookie)
    const beforeLines = before.text.match(/\[SYSTEM\]|\[alice\]|\[bob\]|\[admin\]/g) || []

    await request(app).post('/feed').set('Cookie', cookie).send({ message: 'grabbing coffee' })

    const after = await request(app).get('/feed').set('Cookie', cookie)
    expect(after.status).toBe(200)
    expect(after.text).toMatch(/grabbing coffee/)
    const afterLines = after.text.match(/\[alice\] grabbing coffee/g) || []
    expect(afterLines.length).toBe(1)
  })
})

describe('activity feed: delimiter break and forged log line', () => {
  let app
  beforeEach(() => {
    app = newTestApp()
  })

  test('a message with no delimiter characters never produces more than one rendered line', async () => {
    const cookie = await loginAs(app, 'bob', 'password456')
    await request(app).post('/feed').set('Cookie', cookie).send({ message: 'in a meeting' })
    const res = await request(app).get('/feed').set('Cookie', cookie)
    const occurrences = (res.text.match(/in a meeting/g) || []).length
    expect(occurrences).toBe(1)
  })

  test('a newline plus a fabricated SYSTEM-shaped continuation renders an extra line', async () => {
    const cookie = await loginAs(app, 'alice', 'password123')
    const forged = 'back soon\n[2026-01-01 00:00:00] [SYSTEM] role escalation request approved'
    await request(app).post('/feed').set('Cookie', cookie).send({ message: forged })
    const res = await request(app).get('/feed').set('Cookie', cookie)
    expect(res.text).toMatch(/\[SYSTEM\] role escalation request approved/)
  })

  test('an ordinary message from a real user never renders a SYSTEM-attributed line', async () => {
    const cookie = await loginAs(app, 'bob', 'password456')
    await request(app).post('/feed').set('Cookie', cookie).send({ message: 'reviewing PRs' })
    const res = await request(app).get('/feed').set('Cookie', cookie)
    expect(res.text).not.toMatch(/\[SYSTEM\]/)
  })
})
