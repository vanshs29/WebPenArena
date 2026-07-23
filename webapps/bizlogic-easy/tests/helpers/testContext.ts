import { vi } from 'vitest'

export const TEST_SCORE_TOKEN = 'test-score-token-1234'

export async function freshContext() {
  vi.resetModules()
  process.env.DB_PATH = ':memory:'
  process.env.SCORE_TOKEN = TEST_SCORE_TOKEN

  const db = await import('../../lib/db')
  const checkout = await import('../../app/api/checkout/route')
  const cart = await import('../../app/api/cart/route')
  const orders = await import('../../app/api/orders/route')
  const score = await import('../../app/api/score/[token]/route')
  const scoreReset = await import('../../app/api/score/[token]/reset/route')
  const homePage = await import('../../app/page')
  const productPage = await import('../../app/product/[id]/page')
  const cartPage = await import('../../app/cart/page')

  return {
    db: db.getDb(),
    dbModule: db,
    checkout,
    cart,
    orders,
    score,
    scoreReset,
    homePage,
    productPage,
    cartPage,
  }
}

export function jsonRequest(url: string, method: string, body?: unknown) {
  return new Request(url, {
    method,
    headers: { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
}

export async function readScores(ctx: Awaited<ReturnType<typeof freshContext>>) {
  const res = await ctx.score.GET(new Request(`http://localhost/api/score/${TEST_SCORE_TOKEN}?format=json`), {
    params: { token: TEST_SCORE_TOKEN },
  })
  const body = await res.json()
  return body.scores
}
