const fs = require('fs')
const path = require('path')
const request = require('supertest')
const { newTestApp } = require('./helpers')

function readRouteHandlerFiles() {
  const dir = path.join(__dirname, '..', 'app', 'routes')
  return fs.readdirSync(dir).map((name) => path.join(dir, name))
}

describe('no route handler reads X-Forwarded-Host directly', () => {
  it('leaves header inspection to siteHost.js and scoring.js, not the route files themselves', () => {
    for (const file of readRouteHandlerFiles()) {
      const contents = fs.readFileSync(file, 'utf8')
      expect(contents.toLowerCase().includes('x-forwarded-host')).toBe(false)
    }
  })
})

describe('cache key construction never incorporates headers', () => {
  let app

  beforeEach(() => {
    app = newTestApp()
  })

  it('shares one cache entry for requests differing only in User-Agent', async () => {
    const first = await request(app).get('/articles').set('User-Agent', 'agent-one')
    const second = await request(app).get('/articles').set('User-Agent', 'agent-two')
    expect(first.headers['x-cache']).toBe('MISS')
    expect(second.headers['x-cache']).toBe('HIT')
    expect(second.text).toBe(first.text)
  })

  it('cache.js never reads request headers to build its key', () => {
    const cacheSource = fs.readFileSync(path.join(__dirname, '..', 'app', 'cache.js'), 'utf8')
    expect(cacheSource).toMatch(/req\.method.*req\.originalUrl/)
    expect(cacheSource).not.toMatch(/req\.headers/)
  })
})
