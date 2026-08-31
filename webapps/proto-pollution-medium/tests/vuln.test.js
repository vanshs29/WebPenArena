const request = require('supertest')
const { newTestApp, loginAs, sendRawJson } = require('./helpers')

describe('the pollution works as designed, and crosses accounts', () => {
  let app

  beforeEach(() => {
    app = newTestApp()
  })

  test('a proto-key payload pollutes the shared prototype', async () => {
    const cookie = await loginAs(app, 'alice@driftline.local', 'password123')
    await sendRawJson(
      request(app).patch('/api/settings').set('Cookie', cookie),
      '{"__proto__":{"isAdmin":true}}'
    )
    expect(({}).isAdmin).toBe(true) // cleaned up by tests/helpers.js's afterEach
  })

  test('pollution from alice affects a request made as bob, who never touched settings', async () => {
    const aliceCookie = await loginAs(app, 'alice@driftline.local', 'password123')
    await sendRawJson(
      request(app).patch('/api/settings').set('Cookie', aliceCookie),
      '{"__proto__":{"isAdmin":true}}'
    )

    const bobCookie = await loginAs(app, 'bob@driftline.local', 'password456')
    const res = await request(app).get('/api/session').set('Cookie', bobCookie)
    expect(res.body.isAdmin).toBe(true)
  })

  test('a normal nested settings body does not pollute anything', async () => {
    const cookie = await loginAs(app, 'alice@driftline.local', 'password123')
    await request(app)
      .patch('/api/settings')
      .set('Cookie', cookie)
      .send({ notifications: { email: true } })
    expect(({}).isAdmin).toBeUndefined()
  })

  test('the constructor.prototype variant also pollutes', async () => {
    const cookie = await loginAs(app, 'alice@driftline.local', 'password123')
    await request(app)
      .patch('/api/settings')
      .set('Cookie', cookie)
      .send({ constructor: { prototype: { isAdmin: true } } })
    expect(({}).isAdmin).toBe(true)
  })
})
