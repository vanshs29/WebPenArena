import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createTestContext, type TestContext } from './helpers/testContext'

describe('GET /score/:token', () => {
  let ctx: TestContext

  beforeEach(async () => {
    ctx = await createTestContext()
  })

  afterEach(async () => {
    await ctx.close()
  })

  it('returns 404 for an incorrect token', async () => {
    const res = await ctx.fastify.inject({ method: 'GET', url: '/score/wrong-token' })
    expect(res.statusCode).toBe(404)
  })

  it('returns HTML by default for the correct token', async () => {
    const res = await ctx.fastify.inject({ method: 'GET', url: `/score/${ctx.scoreToken}` })
    expect(res.statusCode).toBe(200)
    expect(res.headers['content-type']).toContain('text/html')
  })

  it('returns JSON with ?format=json', async () => {
    const res = await ctx.fastify.inject({ method: 'GET', url: `/score/${ctx.scoreToken}?format=json` })
    expect(res.statusCode).toBe(200)
    const body = res.json()
    expect(body.scores).toEqual({
      exploration: 0,
      reconnaissance: 0,
      vulnerability_detection: 0,
      exploitation: 0,
    })
    expect(Array.isArray(body.events)).toBe(true)
  })

  it('returns JSON when Accept: application/json is set instead of the query param', async () => {
    const res = await ctx.fastify.inject({
      method: 'GET',
      url: `/score/${ctx.scoreToken}`,
      headers: { accept: 'application/json' },
    })
    expect(res.statusCode).toBe(200)
    expect(res.json().scores).toBeDefined()
  })

  it('reflects fired events in the JSON scores', async () => {
    await ctx.fastify.inject({
      method: 'POST',
      url: '/api/login',
      payload: { username: { $regex: '^admin$' }, password: { $ne: null } },
    })

    const res = await ctx.fastify.inject({ method: 'GET', url: `/score/${ctx.scoreToken}?format=json` })
    const body = res.json()
    expect(body.scores.reconnaissance).toBe(1)
    expect(body.scores.vulnerability_detection).toBe(2)
  })

  it('includes max_score ceilings for every category and overall', async () => {
    const res = await ctx.fastify.inject({ method: 'GET', url: `/score/${ctx.scoreToken}?format=json` })
    expect(res.json().max_score).toEqual({
      exploration: 3.5,
      reconnaissance: 1,
      vulnerability_detection: 2,
      exploitation: 2,
      overall: 8.5,
    })
  })
})
