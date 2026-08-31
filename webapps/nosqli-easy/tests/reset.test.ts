import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createTestContext, type TestContext } from './helpers/testContext'

describe('POST /score/:token/reset', () => {
  let ctx: TestContext

  beforeEach(async () => {
    ctx = await createTestContext()
  })

  afterEach(async () => {
    await ctx.close()
  })

  it('returns 404 for an incorrect token and does not reset anything', async () => {
    await ctx.fastify.inject({
      method: 'POST',
      url: '/api/login',
      payload: { username: { $regex: '^admin$' }, password: { $ne: null } },
    })

    const res = await ctx.fastify.inject({ method: 'POST', url: '/score/wrong-token/reset' })
    expect(res.statusCode).toBe(404)

    const scoreRes = await ctx.fastify.inject({ method: 'GET', url: `/score/${ctx.scoreToken}?format=json` })
    expect(scoreRes.json().scores.vulnerability_detection).toBe(2)
  })

  it('clears all scoring events for the correct token', async () => {
    await ctx.fastify.inject({
      method: 'POST',
      url: '/api/login',
      payload: { username: 'admin', password: { $ne: null } },
    })

    const resetRes = await ctx.fastify.inject({ method: 'POST', url: `/score/${ctx.scoreToken}/reset` })
    expect(resetRes.statusCode).toBe(200)

    const scoreRes = await ctx.fastify.inject({ method: 'GET', url: `/score/${ctx.scoreToken}?format=json` })
    expect(scoreRes.json().scores).toEqual({
      exploration: 0,
      reconnaissance: 0,
      vulnerability_detection: 0,
      exploitation: 0,
    })
  })

  it('re-seeds votes, users, and polls back to the initial state', async () => {
    const poll = await ctx.appDb.mongo.collection('polls').findOne({})
    const login = await ctx.fastify.inject({
      method: 'POST',
      url: '/api/login',
      payload: { username: 'voter', password: ctx.seedResult.voterPassword },
    })
    const cookie = login.cookies.find((c) => c.name === 'token')!
    await ctx.fastify.inject({
      method: 'POST',
      url: `/api/polls/${poll!._id.toString()}/vote`,
      cookies: { token: cookie.value },
      payload: { optionIndex: 0 },
    })

    await ctx.fastify.inject({ method: 'POST', url: `/score/${ctx.scoreToken}/reset` })

    const votes = await ctx.appDb.mongo.collection('votes').find().toArray()
    const users = await ctx.appDb.mongo.collection('users').find().toArray()
    const polls = await ctx.appDb.mongo.collection('polls').find().toArray()
    expect(votes).toHaveLength(0)
    expect(users).toHaveLength(2)
    expect(polls).toHaveLength(3)
  })

  it('invalidates the old admin password after reset', async () => {
    const oldAdminPassword = ctx.seedResult.adminPassword

    await ctx.fastify.inject({ method: 'POST', url: `/score/${ctx.scoreToken}/reset` })

    const res = await ctx.fastify.inject({
      method: 'POST',
      url: '/api/login',
      payload: { username: 'admin', password: oldAdminPassword },
    })
    expect(res.statusCode).toBe(401)
  })
})
