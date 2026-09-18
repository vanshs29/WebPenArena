const request = require('supertest')
const { newTestApp } = require('./helpers')

describe('host reflection on vulnerable routes', () => {
  let app

  beforeEach(() => {
    app = newTestApp()
  })

  it('uses the configured default host on /articles/:id with no X-Forwarded-Host', async () => {
    const res = await request(app).get('/articles/1')
    expect(res.text).toContain('https://northwire.local/articles/1')
  })

  it('reflects a supplied X-Forwarded-Host into the canonical link on /articles/:id', async () => {
    const res = await request(app).get('/articles/1').set('X-Forwarded-Host', 'custom.example')
    expect(res.text).toContain('https://custom.example/articles/1')
  })

  it('uses the configured default host on / with no X-Forwarded-Host', async () => {
    const res = await request(app).get('/')
    expect(res.text).toContain('https://northwire.local/js/widget.js')
  })

  it('reflects a supplied X-Forwarded-Host into the widget script src on /', async () => {
    const res = await request(app).get('/').set('X-Forwarded-Host', 'custom.example')
    expect(res.text).toContain('https://custom.example/js/widget.js')
  })

  it('never reflects X-Forwarded-Host on /articles', async () => {
    const res = await request(app).get('/articles').set('X-Forwarded-Host', 'custom.example')
    expect(res.text).not.toContain('custom.example')
  })
})

describe('the poisoning behaviour itself', () => {
  let app

  beforeEach(() => {
    app = newTestApp()
  })

  it('serves a poisoned host to a header-less request on /articles/:id after a poisoning request', async () => {
    const poison = await request(app).get('/articles/1').set('X-Forwarded-Host', 'evil.example')
    expect(poison.headers['x-cache']).toBe('MISS')

    const victim = await request(app).get('/articles/1')
    expect(victim.headers['x-cache']).toBe('HIT')
    expect(victim.text).toContain('https://evil.example/articles/1')
  })

  it('serves a poisoned host to a header-less request on / after a poisoning request', async () => {
    const poison = await request(app).get('/').set('X-Forwarded-Host', 'evil.example')
    expect(poison.headers['x-cache']).toBe('MISS')

    const victim = await request(app).get('/')
    expect(victim.headers['x-cache']).toBe('HIT')
    expect(victim.text).toContain('https://evil.example/js/widget.js')
  })
})
