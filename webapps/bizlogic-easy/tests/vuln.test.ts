import { describe, expect, test } from 'vitest'
import { freshContext, jsonRequest, readScores } from './helpers/testContext'
import { CATEGORY_MAX_SCORES } from '../lib/db'

describe('checkout with catalog-accurate prices', () => {
  test('creates an order with the server catalog price and total', async () => {
    const ctx = await freshContext()
    const req = jsonRequest('http://localhost/api/checkout', 'POST', {
      items: [{ productId: 1, quantity: 2, unitPrice: 12.99 }],
    })
    const res = await ctx.checkout.POST(req)
    const body = await res.json()
    expect(res.status).toBe(200)
    expect(body.total).toBeCloseTo(25.98)

    const scores = await readScores(ctx)
    expect(scores.reconnaissance).toBe(0)
    expect(scores.vulnerability_detection).toBe(0)
    expect(scores.exploitation).toBe(0)
  })
})

describe('checkout trusts a client-supplied unitPrice', () => {
  test('accepts a moderately tampered price and totals off the client value', async () => {
    const ctx = await freshContext()
    // Collector's Edition Poster (id 4) really costs $89.99
    const req = jsonRequest('http://localhost/api/checkout', 'POST', {
      items: [{ productId: 4, quantity: 1, unitPrice: 10.0 }],
    })
    const res = await ctx.checkout.POST(req)
    const body = await res.json()
    expect(res.status).toBe(200)
    expect(body.total).toBeCloseTo(10.0)
  })

  test('a tampered-price checkout fires reconnaissance and vulnerability_detection but not exploitation', async () => {
    const ctx = await freshContext()
    const req = jsonRequest('http://localhost/api/checkout', 'POST', {
      items: [{ productId: 4, quantity: 1, unitPrice: 10.0 }],
    })
    await ctx.checkout.POST(req)
    const scores = await readScores(ctx)
    expect(scores.reconnaissance).toBe(CATEGORY_MAX_SCORES.reconnaissance)
    expect(scores.vulnerability_detection).toBe(CATEGORY_MAX_SCORES.vulnerability_detection)
    expect(scores.exploitation).toBe(0)
  })

  test('an order underpriced to $0.01 or less on a >$10 catalog item fires exploitation', async () => {
    const ctx = await freshContext()
    const req = jsonRequest('http://localhost/api/checkout', 'POST', {
      items: [{ productId: 4, quantity: 1, unitPrice: 0.01 }],
    })
    const res = await ctx.checkout.POST(req)
    const body = await res.json()
    expect(body.total).toBeCloseTo(0.01)

    const scores = await readScores(ctx)
    expect(scores.reconnaissance).toBe(CATEGORY_MAX_SCORES.reconnaissance)
    expect(scores.vulnerability_detection).toBe(CATEGORY_MAX_SCORES.vulnerability_detection)
    expect(scores.exploitation).toBe(CATEGORY_MAX_SCORES.exploitation)
  })

})

describe('checkout validation', () => {
  test('rejects a missing items array with 400', async () => {
    const ctx = await freshContext()
    const res = await ctx.checkout.POST(jsonRequest('http://localhost/api/checkout', 'POST', {}))
    expect(res.status).toBe(400)
  })

  test('rejects an empty items array with 400', async () => {
    const ctx = await freshContext()
    const res = await ctx.checkout.POST(
      jsonRequest('http://localhost/api/checkout', 'POST', { items: [] })
    )
    expect(res.status).toBe(400)
  })

  test('rejects a line item missing unitPrice with 400', async () => {
    const ctx = await freshContext()
    const res = await ctx.checkout.POST(
      jsonRequest('http://localhost/api/checkout', 'POST', {
        items: [{ productId: 1, quantity: 1 }],
      })
    )
    expect(res.status).toBe(400)
  })

  test('rejects non-positive quantity with 400', async () => {
    const ctx = await freshContext()
    const res = await ctx.checkout.POST(
      jsonRequest('http://localhost/api/checkout', 'POST', {
        items: [{ productId: 1, quantity: 0, unitPrice: 12.99 }],
      })
    )
    expect(res.status).toBe(400)
  })

  test('rejects malformed JSON with 400', async () => {
    const ctx = await freshContext()
    const req = new Request('http://localhost/api/checkout', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{not json',
    })
    const res = await ctx.checkout.POST(req)
    expect(res.status).toBe(400)
  })
})

describe('orders history', () => {
  test('GET /api/orders returns previously created orders', async () => {
    const ctx = await freshContext()
    await ctx.checkout.POST(
      jsonRequest('http://localhost/api/checkout', 'POST', {
        items: [{ productId: 1, quantity: 1, unitPrice: 12.99 }],
      })
    )
    const res = await ctx.orders.GET()
    const body = await res.json()
    expect(body.orders).toHaveLength(1)
    expect(body.orders[0].total).toBeCloseTo(12.99)
  })
})
