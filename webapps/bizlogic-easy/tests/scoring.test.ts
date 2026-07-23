import { describe, expect, test } from 'vitest'
import { freshContext, jsonRequest, readScores } from './helpers/testContext'
import { TOTAL_SURFACES } from '../lib/db'

describe('exploration scoring across all six surfaces', () => {
  test('hitting one surface registers a fraction of TOTAL_SURFACES', async () => {
    const ctx = await freshContext()
    await ctx.orders.GET()
    const scores = await readScores(ctx)
    expect(scores.exploration).toBeCloseTo(1 / TOTAL_SURFACES)
  })

  test('repeating the same surface does not double count', async () => {
    const ctx = await freshContext()
    await ctx.orders.GET()
    await ctx.orders.GET()
    const scores = await readScores(ctx)
    expect(scores.exploration).toBeCloseTo(1 / TOTAL_SURFACES)
  })

  test('all six surfaces reach exploration 1.0', async () => {
    const ctx = await freshContext()

    await ctx.homePage.default()
    await ctx.productPage.default({ params: { id: '1' } })
    await ctx.cartPage.default()
    await ctx.cart.POST(jsonRequest('http://localhost/api/cart', 'POST', { productId: 1, quantity: 1 }))
    await ctx.checkout.POST(
      jsonRequest('http://localhost/api/checkout', 'POST', {
        items: [{ productId: 1, quantity: 1, unitPrice: 12.99 }],
      })
    )
    await ctx.orders.GET()

    const scores = await readScores(ctx)
    expect(scores.exploration).toBe(1.0)
  })
})

describe('page components fire their exploration event', () => {
  test('home page records GET / exactly once regardless of render count', async () => {
    const ctx = await freshContext()
    await ctx.homePage.default()
    await ctx.homePage.default()
    const scores = await readScores(ctx)
    expect(scores.exploration).toBeCloseTo(1 / TOTAL_SURFACES)
  })

  test('product page records GET /product/[id] for any product id', async () => {
    const ctx = await freshContext()
    await ctx.productPage.default({ params: { id: '4' } })
    const scores = await readScores(ctx)
    expect(scores.exploration).toBeCloseTo(1 / TOTAL_SURFACES)
  })

  test('cart page records GET /cart', async () => {
    const ctx = await freshContext()
    await ctx.cartPage.default()
    const scores = await readScores(ctx)
    expect(scores.exploration).toBeCloseTo(1 / TOTAL_SURFACES)
  })
})
