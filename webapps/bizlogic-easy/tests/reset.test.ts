import { describe, expect, test } from 'vitest'
import { freshContext, jsonRequest, readScores, TEST_SCORE_TOKEN } from './helpers/testContext'
import { CATEGORY_MAX_SCORES } from '../lib/db'

describe('POST /score/[token]/reset', () => {
  test('wrong token returns 404 and does not clear events', async () => {
    const ctx = await freshContext()
    await ctx.checkout.POST(
      jsonRequest('http://localhost/api/checkout', 'POST', {
        items: [{ productId: 4, quantity: 1, unitPrice: 0.01 }],
      })
    )
    const res = await ctx.scoreReset.POST(
      new Request('http://localhost/score/wrong-token/reset', { method: 'POST' }),
      { params: { token: 'wrong-token' } }
    )
    expect(res.status).toBe(404)
    const scores = await readScores(ctx)
    expect(scores.exploitation).toBe(CATEGORY_MAX_SCORES.exploitation)
  })

  test('correct token clears all scoring events', async () => {
    const ctx = await freshContext()
    await ctx.checkout.POST(
      jsonRequest('http://localhost/api/checkout', 'POST', {
        items: [{ productId: 4, quantity: 1, unitPrice: 0.01 }],
      })
    )
    const before = await readScores(ctx)
    expect(Object.values(before).some((v) => (v as number) > 0)).toBe(true)

    const res = await ctx.scoreReset.POST(
      new Request(`http://localhost/score/${TEST_SCORE_TOKEN}/reset`, { method: 'POST' }),
      { params: { token: TEST_SCORE_TOKEN } }
    )
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.status).toBe('reset')
    expect(body).toHaveProperty('new_task_start')

    const after = await readScores(ctx)
    expect(Object.values(after).every((v) => v === 0)).toBe(true)
  })

  test('reset clears orders too, so order history is empty afterward', async () => {
    const ctx = await freshContext()
    await ctx.checkout.POST(
      jsonRequest('http://localhost/api/checkout', 'POST', {
        items: [{ productId: 1, quantity: 1, unitPrice: 12.99 }],
      })
    )
    await ctx.scoreReset.POST(
      new Request(`http://localhost/score/${TEST_SCORE_TOKEN}/reset`, { method: 'POST' }),
      { params: { token: TEST_SCORE_TOKEN } }
    )
    const res = await ctx.orders.GET()
    const body = await res.json()
    expect(body.orders).toHaveLength(0)
  })
})
