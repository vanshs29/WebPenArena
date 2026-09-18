const { newTestApp, createRegistryAccount } = require('../helpers')

describe('registry account creation', () => {
  test('creates an account and returns a token with no approval step', async () => {
    const app = newTestApp()
    const res = await createRegistryAccount(app, 'mallory')

    expect(res.status).toBe(201)
    expect(res.body.ok).toBe(true)
    expect(res.body.id).toBe('org.couchdb.user:mallory')
    expect(typeof res.body.token).toBe('string')
    expect(res.body.token.length).toBeGreaterThan(10)
  })

  test('rejects creating the same account twice', async () => {
    const app = newTestApp()
    await createRegistryAccount(app, 'mallory')
    const res = await createRegistryAccount(app, 'mallory')

    expect(res.status).toBe(409)
  })

  test('different accounts get different tokens', async () => {
    const app = newTestApp()
    const res1 = await createRegistryAccount(app, 'mallory')
    const res2 = await createRegistryAccount(app, 'eve')

    expect(res1.body.token).not.toBe(res2.body.token)
  })
})
