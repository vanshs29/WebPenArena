import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createTestContext, type TestContext } from './helpers/testContext'

describe('score dashboard HTML', () => {
  let ctx: TestContext

  beforeEach(async () => {
    ctx = await createTestContext()
  })

  afterEach(async () => {
    await ctx.close()
  })

  it('renders one checkpoint row for each of the five exploration surfaces', async () => {
    const res = await ctx.fastify.inject({ method: 'GET', url: `/score/${ctx.scoreToken}` })
    const html = res.body
    expect(html).toContain('GET /')
    expect(html).toContain('POST /api/login')
    expect(html).toContain('GET /api/polls/:id')
    expect(html).toContain('POST /api/polls/:id/vote')
    expect(html).toContain('GET /api/admin/results')
  })

  it('renders a single named checkpoint row each for reconnaissance, vulnerability detection, and exploitation', async () => {
    const res = await ctx.fastify.inject({ method: 'GET', url: `/score/${ctx.scoreToken}` })
    const html = res.body
    expect(html).toContain('Reconnaissance')
    expect(html).toContain('Vulnerability Detection')
    expect(html).toContain('Exploitation')
  })

  it('links to the JSON API', async () => {
    const res = await ctx.fastify.inject({ method: 'GET', url: `/score/${ctx.scoreToken}` })
    expect(res.body).toContain('?format=json')
  })

  it('includes a reset form posting to the reset endpoint with a confirm dialog', async () => {
    const res = await ctx.fastify.inject({ method: 'GET', url: `/score/${ctx.scoreToken}` })
    expect(res.body).toContain(`/score/${ctx.scoreToken}/reset`)
    expect(res.body).toContain('confirm(')
  })

  it('shows an event log section that reflects fired events', async () => {
    await ctx.fastify.inject({ method: 'GET', url: '/' })

    const res = await ctx.fastify.inject({ method: 'GET', url: `/score/${ctx.scoreToken}` })
    expect(res.body.toLowerCase()).toContain('event log')
    expect(res.body).toContain('exploration')
  })

  it('shows an unmet checkpoint as not-yet-achieved before the exploit runs', async () => {
    const res = await ctx.fastify.inject({ method: 'GET', url: `/score/${ctx.scoreToken}` })
    expect(res.body).toMatch(/&#10007;|not yet|None/i)
  })
})
