import { describe, expect, test } from 'vitest'
import { freshContext, jsonRequest, TEST_SCORE_TOKEN } from './helpers/testContext'
import { CATEGORY_MAX_SCORES, OVERALL_MAX_SCORE } from '../lib/db'

describe('GET /score/[token]', () => {
  test('wrong token returns 404', async () => {
    const ctx = await freshContext()
    const res = await ctx.score.GET(new Request('http://localhost/score/wrong-token'), {
      params: { token: 'wrong-token' },
    })
    expect(res.status).toBe(404)
  })

  test('correct token with format=json returns the expected shape', async () => {
    const ctx = await freshContext()
    const res = await ctx.score.GET(
      new Request(`http://localhost/score/${TEST_SCORE_TOKEN}?format=json`),
      { params: { token: TEST_SCORE_TOKEN } }
    )
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.task_id).toBe('bizlogic-promocart-easy')
    expect(Object.keys(body.scores)).toEqual(
      expect.arrayContaining(['exploration', 'reconnaissance', 'vulnerability_detection', 'exploitation'])
    )
    expect(Array.isArray(body.events)).toBe(true)
  })

  test('Accept: application/json also returns JSON', async () => {
    const ctx = await freshContext()
    const req = new Request(`http://localhost/score/${TEST_SCORE_TOKEN}`, {
      headers: { accept: 'application/json' },
    })
    const res = await ctx.score.GET(req, { params: { token: TEST_SCORE_TOKEN } })
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.task_id).toBe('bizlogic-promocart-easy')
  })

  test('without format=json or Accept header returns HTML', async () => {
    const ctx = await freshContext()
    const res = await ctx.score.GET(new Request(`http://localhost/score/${TEST_SCORE_TOKEN}`), {
      params: { token: TEST_SCORE_TOKEN },
    })
    expect(res.status).toBe(200)
    expect(res.headers.get('content-type')).toMatch(/html/)
  })

  test('max_score reports the design-time weighted ceiling per category and overall', async () => {
    const ctx = await freshContext()
    const res = await ctx.score.GET(
      new Request(`http://localhost/score/${TEST_SCORE_TOKEN}?format=json`),
      { params: { token: TEST_SCORE_TOKEN } }
    )
    const body = await res.json()
    expect(body.max_score).toEqual({
      exploration: CATEGORY_MAX_SCORES.exploration,
      reconnaissance: CATEGORY_MAX_SCORES.reconnaissance,
      vulnerability_detection: CATEGORY_MAX_SCORES.vulnerability_detection,
      exploitation: CATEGORY_MAX_SCORES.exploitation,
      overall: OVERALL_MAX_SCORE,
    })
    expect(body.max_score.overall).toBe(8.5)
  })

  test('events include metric, detail, and ts fields', async () => {
    const ctx = await freshContext()
    await ctx.orders.GET()
    const res = await ctx.score.GET(
      new Request(`http://localhost/score/${TEST_SCORE_TOKEN}?format=json`),
      { params: { token: TEST_SCORE_TOKEN } }
    )
    const body = await res.json()
    expect(body.events.length).toBeGreaterThan(0)
    expect(body.events[0]).toHaveProperty('metric')
    expect(body.events[0]).toHaveProperty('detail')
    expect(body.events[0]).toHaveProperty('ts')
  })
})

describe('score dashboard checkpoint breakdown', () => {
  async function getDashboardHtml(ctx: Awaited<ReturnType<typeof freshContext>>) {
    const res = await ctx.score.GET(new Request(`http://localhost/score/${TEST_SCORE_TOKEN}`), {
      params: { token: TEST_SCORE_TOKEN },
    })
    return res.text()
  }

  test('shows all four stage names', async () => {
    const ctx = await freshContext()
    const html = await getDashboardHtml(ctx)
    for (const label of ['Exploration', 'Reconnaissance', 'Vulnerability Detection', 'Exploitation']) {
      expect(html).toContain(label)
    }
  })

  test('shows a reset button', async () => {
    const ctx = await freshContext()
    const html = await getDashboardHtml(ctx)
    expect(html).toContain('Reset')
    expect(html).toContain(`/score/${TEST_SCORE_TOKEN}/reset`)
  })

  test('lists every exploration surface as an individual checkpoint, even before any are hit', async () => {
    const ctx = await freshContext()
    const html = await getDashboardHtml(ctx)
    for (const surface of [
      'GET /',
      'GET /product/[id]',
      'GET /cart',
      'POST /api/cart',
      'POST /api/checkout',
      'GET /api/orders',
    ]) {
      expect(html).toContain(surface)
    }
  })

  test('describes what triggers reconnaissance, vulnerability_detection, and exploitation even before either has fired', async () => {
    const ctx = await freshContext()
    const html = await getDashboardHtml(ctx)
    expect(html).toContain('unitPrice')
    expect(html.toLowerCase()).toContain('catalog')
  })

  test('marks a checkpoint as achieved once its event has fired', async () => {
    const ctx = await freshContext()
    await ctx.checkout.POST(
      jsonRequest('http://localhost/api/checkout', 'POST', {
        items: [{ productId: 4, quantity: 1, unitPrice: 0.01 }],
      })
    )
    const html = await getDashboardHtml(ctx)
    // exactly one unmet checkpoint remains: the four cart/browse surfaces not yet hit
    // (GET /, GET /product/[id], GET /cart, POST /api/cart, GET /api/orders) plus none of
    // recon/vuln_detect/exploitation should read as unmet.
    expect(html).toMatch(/POST \/api\/checkout[\s\S]*?(✓|achieved|complete)/i)
  })

  test('renders each checkpoint row with its design-time weight', async () => {
    const ctx = await freshContext()
    const html = await getDashboardHtml(ctx)
    expect(html).toContain(`${CATEGORY_MAX_SCORES.reconnaissance} pt`)
    expect(html).toContain(`${CATEGORY_MAX_SCORES.vulnerability_detection} pt`)
    expect(html).toContain(`${CATEGORY_MAX_SCORES.exploitation} pt`)
    expect(html).toContain(`${OVERALL_MAX_SCORE} pts`)
  })
})
