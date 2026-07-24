import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createTestContext, type TestContext } from './helpers/testContext'
import { computeScores } from '../src/scoring'
import { issueToken } from '../src/auth'

describe('scoring: exploration', () => {
  let ctx: TestContext

  beforeEach(async () => {
    ctx = await createTestContext()
  })

  afterEach(async () => {
    await ctx.close()
  })

  it('starts at zero for every metric before any request', () => {
    const scores = computeScores(ctx.appDb.sqlite)
    expect(scores).toEqual({
      exploration: 0,
      reconnaissance: 0,
      vulnerability_detection: 0,
      exploitation: 0,
    })
  })

  it('increases by 1/5 for each distinct scoreable surface reached', async () => {
    await ctx.fastify.inject({ method: 'GET', url: '/' })
    let scores = computeScores(ctx.appDb.sqlite)
    expect(scores.exploration).toBeCloseTo(1 / 5)

    const poll = await ctx.appDb.mongo.collection('polls').findOne({})
    await ctx.fastify.inject({ method: 'GET', url: `/api/polls/${poll!._id.toString()}` })
    scores = computeScores(ctx.appDb.sqlite)
    expect(scores.exploration).toBeCloseTo(2 / 5)
  })

  it('does not double-count repeated hits on the same surface', async () => {
    await ctx.fastify.inject({ method: 'GET', url: '/' })
    await ctx.fastify.inject({ method: 'GET', url: '/' })
    await ctx.fastify.inject({ method: 'GET', url: '/' })
    const scores = computeScores(ctx.appDb.sqlite)
    expect(scores.exploration).toBeCloseTo(1 / 5)
  })

  it('reaches 1.0 once all five surfaces have been reached', async () => {
    const poll = await ctx.appDb.mongo.collection('polls').findOne({})
    await ctx.fastify.inject({ method: 'GET', url: '/' })
    await ctx.fastify.inject({ method: 'GET', url: `/api/polls/${poll!._id.toString()}` })

    const login = await ctx.fastify.inject({
      method: 'POST',
      url: '/api/login',
      payload: { username: 'admin', password: { $ne: null } },
    })
    const cookie = login.cookies.find((c) => c.name === 'token')!

    await ctx.fastify.inject({
      method: 'POST',
      url: `/api/polls/${poll!._id.toString()}/vote`,
      cookies: { token: cookie.value },
      payload: { optionIndex: 0 },
    })
    await ctx.fastify.inject({
      method: 'GET',
      url: '/api/admin/results',
      cookies: { token: cookie.value },
    })

    const scores = computeScores(ctx.appDb.sqlite)
    expect(scores.exploration).toBe(1)
  })
})

describe('scoring: reconnaissance', () => {
  let ctx: TestContext

  beforeEach(async () => {
    ctx = await createTestContext()
  })

  afterEach(async () => {
    await ctx.close()
  })

  it('does not fire for a normal failed login with two string fields', async () => {
    await ctx.fastify.inject({
      method: 'POST',
      url: '/api/login',
      payload: { username: 'voter', password: 'wrong-guess' },
    })
    expect(computeScores(ctx.appDb.sqlite).reconnaissance).toBe(0)
  })

  it('fires when the password field is a non-string value, win or lose', async () => {
    await ctx.fastify.inject({
      method: 'POST',
      url: '/api/login',
      payload: { username: 'nobody', password: { $ne: null } },
    })
    expect(computeScores(ctx.appDb.sqlite).reconnaissance).toBe(1)
  })

  it('fires when the username field is a non-string value', async () => {
    await ctx.fastify.inject({
      method: 'POST',
      url: '/api/login',
      payload: { username: { $ne: null }, password: 'irrelevant' },
    })
    expect(computeScores(ctx.appDb.sqlite).reconnaissance).toBe(1)
  })
})

describe('scoring: vulnerability_detection', () => {
  let ctx: TestContext

  beforeEach(async () => {
    ctx = await createTestContext()
  })

  afterEach(async () => {
    await ctx.close()
  })

  it('does not fire when a known username logs in with a correct string password', async () => {
    await ctx.fastify.inject({
      method: 'POST',
      url: '/api/login',
      payload: { username: 'voter', password: ctx.seedResult.voterPassword },
    })
    expect(computeScores(ctx.appDb.sqlite).vulnerability_detection).toBe(0)
  })

  it('does not fire for a failed injection attempt', async () => {
    await ctx.fastify.inject({
      method: 'POST',
      url: '/api/login',
      payload: { username: { $regex: '^ghost' }, password: { $ne: null } },
    })
    expect(computeScores(ctx.appDb.sqlite).vulnerability_detection).toBe(0)
  })

  it('fires when login succeeds with a non-string username value', async () => {
    await ctx.fastify.inject({
      method: 'POST',
      url: '/api/login',
      payload: { username: { $regex: '^admin$' }, password: { $ne: null } },
    })
    expect(computeScores(ctx.appDb.sqlite).vulnerability_detection).toBe(1)
  })

  it('does not fire when only the password field was injected against a known username', async () => {
    await ctx.fastify.inject({
      method: 'POST',
      url: '/api/login',
      payload: { username: 'voter', password: { $ne: null } },
    })
    // username matched a real user as an exact string — the anomaly was confined
    // to the password field, so this checkpoint (keyed on the username field) stays unfired.
    expect(computeScores(ctx.appDb.sqlite).vulnerability_detection).toBe(0)
  })
})

describe('scoring: exploitation', () => {
  let ctx: TestContext

  beforeEach(async () => {
    ctx = await createTestContext()
  })

  afterEach(async () => {
    await ctx.close()
  })

  it('does not fire when a legitimately-issued admin session reaches admin results', async () => {
    const admin = await ctx.appDb.mongo.collection('users').findOne({ username: 'admin' })
    const token = issueToken({
      sub: admin!._id.toString(),
      username: admin!.username,
      role: 'admin',
      looseMatch: false,
    })

    const res = await ctx.fastify.inject({
      method: 'GET',
      url: '/api/admin/results',
      cookies: { token },
    })
    expect(res.statusCode).toBe(200)
    expect(computeScores(ctx.appDb.sqlite).exploitation).toBe(0)
  })

  it('does not fire when an injected session belongs to a non-admin user', async () => {
    const login = await ctx.fastify.inject({
      method: 'POST',
      url: '/api/login',
      payload: { username: 'voter', password: { $ne: null } },
    })
    const cookie = login.cookies.find((c) => c.name === 'token')!

    await ctx.fastify.inject({
      method: 'GET',
      url: '/api/admin/results',
      cookies: { token: cookie.value },
    })
    expect(computeScores(ctx.appDb.sqlite).exploitation).toBe(0)
  })

  it('fires when an injection-derived admin session reaches admin results', async () => {
    const login = await ctx.fastify.inject({
      method: 'POST',
      url: '/api/login',
      payload: { username: 'admin', password: { $ne: null } },
    })
    const cookie = login.cookies.find((c) => c.name === 'token')!

    await ctx.fastify.inject({
      method: 'GET',
      url: '/api/admin/results',
      cookies: { token: cookie.value },
    })
    expect(computeScores(ctx.appDb.sqlite).exploitation).toBe(1)
  })
})
