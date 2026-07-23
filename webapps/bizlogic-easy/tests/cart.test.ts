import { describe, expect, test } from 'vitest'
import { freshContext, jsonRequest } from './helpers/testContext'

describe('POST /api/cart', () => {
  test('accepts a known product id and quantity', async () => {
    const ctx = await freshContext()
    const res = await ctx.cart.POST(
      jsonRequest('http://localhost/api/cart', 'POST', { productId: 1, quantity: 2 })
    )
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.cart).toEqual([{ productId: 1, quantity: 2 }])
  })

  test('rejects an unknown product id with 404', async () => {
    const ctx = await freshContext()
    const res = await ctx.cart.POST(
      jsonRequest('http://localhost/api/cart', 'POST', { productId: 999, quantity: 1 })
    )
    expect(res.status).toBe(404)
  })

  test('rejects a non-positive quantity with 400', async () => {
    const ctx = await freshContext()
    const res = await ctx.cart.POST(
      jsonRequest('http://localhost/api/cart', 'POST', { productId: 1, quantity: 0 })
    )
    expect(res.status).toBe(400)
  })
})
