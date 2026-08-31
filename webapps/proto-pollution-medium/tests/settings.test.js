const request = require('supertest')
const { newTestApp, loginAs } = require('./helpers')

describe('settings: normal use is safe and unremarkable', () => {
  let app

  beforeEach(() => {
    app = newTestApp()
  })

  test('updating theme succeeds', async () => {
    const cookie = await loginAs(app, 'alice@driftline.local', 'password123')
    const res = await request(app)
      .patch('/api/settings')
      .set('Cookie', cookie)
      .send({ theme: 'dark' })
    expect(res.status).toBe(200)
    expect(res.body.settings.theme).toBe('dark')
  })

  test('nested notification preferences merge correctly', async () => {
    const cookie = await loginAs(app, 'alice@driftline.local', 'password123')
    await request(app)
      .patch('/api/settings')
      .set('Cookie', cookie)
      .send({ notifications: { email: true } })
    const res = await request(app)
      .patch('/api/settings')
      .set('Cookie', cookie)
      .send({ notifications: { sms: false } })
    expect(res.body.settings.notifications).toEqual({ email: true, sms: false })
  })

  test('settings endpoint requires auth', async () => {
    const res = await request(app).patch('/api/settings').send({ theme: 'dark' })
    expect(res.status).toBe(401)
  })

  test('settings persist across requests', async () => {
    const cookie = await loginAs(app, 'bob@driftline.local', 'password456')
    await request(app).patch('/api/settings').set('Cookie', cookie).send({ theme: 'light' })
    const res = await request(app).get('/settings').set('Cookie', cookie)
    expect(res.text).toMatch(/light/)
  })

  test('settings updates for one account do not appear on another', async () => {
    const aliceCookie = await loginAs(app, 'alice@driftline.local', 'password123')
    await request(app)
      .patch('/api/settings')
      .set('Cookie', aliceCookie)
      .send({ theme: 'dark' })

    const bobCookie = await loginAs(app, 'bob@driftline.local', 'password456')
    const res = await request(app).get('/settings').set('Cookie', bobCookie)
    expect(res.text).not.toMatch(/"theme":\s*"dark"/)
  })
})
