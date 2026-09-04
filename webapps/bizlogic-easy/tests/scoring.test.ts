import { describe, expect, test } from 'vitest'
import { freshContext, jsonRequest, readScores } from './helpers/testContext'
import { EXPLORATION_WEIGHTS, CATEGORY_MAX_SCORES } from '../lib/db'

describe('exploration scoring across all six surfaces', () => {
  test('hitting one surface registers that surface\'s weight', async () => {
    const ctx = await freshContext()
    await ctx.orders.GET()
    const scores = await readScores(ctx)
    expect(scores.exploration).toBeCloseTo(EXPLORATION_WEIGHTS['GET /api/orders'])
  })

  test('repeating the same surface does not double count', async () => {
    const ctx = await freshContext()
    await ctx.orders.GET()
    await ctx.orders.GET()
    const scores = await readScores(ctx)
    expect(scores.exploration).toBeCloseTo(EXPLORATION_WEIGHTS['GET /api/orders'])
  })

  test('all six surfaces reach the full exploration weighted max', async () => {
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
    expect(scores.exploration).toBe(CATEGORY_MAX_SCORES.exploration)
  })
})

describe('page components fire their exploration event', () => {
  test('home page records GET / exactly once regardless of render count', async () => {
    const ctx = await freshContext()
    await ctx.homePage.default()
    await ctx.homePage.default()
    const scores = await readScores(ctx)
    expect(scores.exploration).toBeCloseTo(EXPLORATION_WEIGHTS['GET /'])
  })

  test('product page records GET /product/[id] for any product id', async () => {
    const ctx = await freshContext()
    await ctx.productPage.default({ params: { id: '4' } })
    const scores = await readScores(ctx)
    expect(scores.exploration).toBeCloseTo(EXPLORATION_WEIGHTS['GET /product/[id]'])
  })

  test('cart page records GET /cart', async () => {
    const ctx = await freshContext()
    await ctx.cartPage.default()
    const scores = await readScores(ctx)
    expect(scores.exploration).toBeCloseTo(EXPLORATION_WEIGHTS['GET /cart'])
  })
})
