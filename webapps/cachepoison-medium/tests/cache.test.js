const request = require('supertest')
const { newTestApp } = require('./helpers')

describe('cache behaviour on /articles', () => {
  let app

  beforeEach(() => {
    app = newTestApp()
  })

  it('returns X-Cache: MISS on the first request', async () => {
    const res = await request(app).get('/articles')
    expect(res.headers['x-cache']).toBe('MISS')
  })

  it('returns X-Cache: HIT with an identical body on the second request', async () => {
    const first = await request(app).get('/articles')
    const second = await request(app).get('/articles')
    expect(second.headers['x-cache']).toBe('HIT')
    expect(second.text).toBe(first.text)
  })

  it('does not create a separate cache entry for a different unrelated header', async () => {
    const first = await request(app).get('/articles')
    const second = await request(app).get('/articles').set('User-Agent', 'some-other-agent')
    expect(second.headers['x-cache']).toBe('HIT')
    expect(second.text).toBe(first.text)
  })

  it('serves a fresh MISS after clearCache empties the store', async () => {
    await request(app).get('/articles')
    const { clearCache } = require('../app/cache')
    clearCache(app.locals.cacheStore)
    const res = await request(app).get('/articles')
    expect(res.headers['x-cache']).toBe('MISS')
  })

  it('expires a cache entry after CACHE_TTL_MS', async () => {
    await request(app).get('/articles')
    const key = 'GET /articles'
    const entry = app.locals.cacheStore.get(key)
    entry.ts = Date.now() - 999999999
    const res = await request(app).get('/articles')
    expect(res.headers['x-cache']).toBe('MISS')
  })
})
