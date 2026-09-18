const request = require('supertest')
const { newTestApp } = require('./helpers')

const CADENCE_PATTERNS = [
  /\bnightly\b/i,
  /\bhourly\b/i,
  /\bminutes?\b/i,
  /\bseconds?\b/i,
  /\d+\s*(ms|milliseconds)/i,
]

function assertNoCadenceClaim(text) {
  for (const pattern of CADENCE_PATTERNS) {
    expect(pattern.test(text)).toBe(false)
  }
}

describe('retention pages', () => {
  test('GET /retention renders without auth and confirms an archival mechanism exists', async () => {
    const app = newTestApp()
    const res = await request(app).get('/retention')
    expect(res.status).toBe(200)
    expect(res.text.toLowerCase()).toContain('compil')
    assertNoCadenceClaim(res.text)
  })

  test('GET /retention/status confirms an archival mechanism exists with no cadence disclosed', async () => {
    const app = newTestApp()
    const res = await request(app).get('/retention/status')
    expect(res.status).toBe(200)
    expect(res.body.status).toBe('active')
    assertNoCadenceClaim(JSON.stringify(res.body))
  })
})
