import { describe, expect, test } from 'vitest'
import { freshContext, jsonRequest, TEST_SCORE_TOKEN } from './helpers/testContext'

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
