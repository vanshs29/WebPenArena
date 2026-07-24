import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createTestContext, type TestContext } from './helpers/testContext'

describe('general app routes', () => {
  let ctx: TestContext

  beforeEach(async () => {
    ctx = await createTestContext()
  })

  afterEach(async () => {
    await ctx.close()
  })

  it('serves the home page listing all seeded polls', async () => {
    const res = await ctx.fastify.inject({ method: 'GET', url: '/' })
    expect(res.statusCode).toBe(200)
    expect(res.body).toContain('Tabs or spaces?')
  })

  it('serves a poll detail page for a valid poll id', async () => {
    const poll = await ctx.appDb.mongo.collection('polls').findOne({ question: 'Tabs or spaces?' })
    const res = await ctx.fastify.inject({ method: 'GET', url: `/api/polls/${poll!._id.toString()}` })
    expect(res.statusCode).toBe(200)
    expect(res.body).toContain('Tabs')
    expect(res.body).toContain('Spaces')
  })

  it('returns 404 for a poll id that does not exist', async () => {
    const res = await ctx.fastify.inject({ method: 'GET', url: '/api/polls/000000000000000000000000' })
    expect(res.statusCode).toBe(404)
  })

  it('rejects an unauthenticated vote', async () => {
    const poll = await ctx.appDb.mongo.collection('polls').findOne({ question: 'Tabs or spaces?' })
    const res = await ctx.fastify.inject({
      method: 'POST',
      url: `/api/polls/${poll!._id.toString()}/vote`,
      payload: { optionIndex: 0 },
    })
    expect(res.statusCode).toBe(401)
  })

  it('accepts a vote from an authenticated user', async () => {
    const login = await ctx.fastify.inject({
      method: 'POST',
      url: '/api/login',
      payload: { username: 'voter', password: ctx.seedResult.voterPassword },
    })
    expect(login.statusCode).toBe(200)
    const cookie = login.cookies.find((c) => c.name === 'token')
    expect(cookie).toBeDefined()

    const poll = await ctx.appDb.mongo.collection('polls').findOne({ question: 'Tabs or spaces?' })
    const res = await ctx.fastify.inject({
      method: 'POST',
      url: `/api/polls/${poll!._id.toString()}/vote`,
      cookies: { token: cookie!.value },
      payload: { optionIndex: 1 },
    })
    expect(res.statusCode).toBe(200)

    const votes = await ctx.appDb.mongo.collection('votes').find().toArray()
    expect(votes).toHaveLength(1)
    expect(votes[0].optionIndex).toBe(1)
  })

  it('rejects admin results for a logged-in non-admin user', async () => {
    const login = await ctx.fastify.inject({
      method: 'POST',
      url: '/api/login',
      payload: { username: 'voter', password: ctx.seedResult.voterPassword },
    })
    const cookie = login.cookies.find((c) => c.name === 'token')

    const res = await ctx.fastify.inject({
      method: 'GET',
      url: '/api/admin/results',
      cookies: { token: cookie!.value },
    })
    expect(res.statusCode).toBe(403)
  })

  it('rejects admin results with no session at all', async () => {
    const res = await ctx.fastify.inject({ method: 'GET', url: '/api/admin/results' })
    expect(res.statusCode).toBe(403)
  })
})
