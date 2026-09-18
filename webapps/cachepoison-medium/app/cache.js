const CACHE_TTL_MS = Number(process.env.CACHE_TTL_MS || 3600000)

function createCacheStore() {
  return new Map()
}

function cacheable() {
  return (req, res, next) => {
    const store = req.app.locals.cacheStore
    const key = `${req.method} ${req.originalUrl}`
    const cached = store.get(key)
    if (cached && Date.now() - cached.ts < CACHE_TTL_MS) {
      res.set('X-Cache', 'HIT')
      req.cacheOutcome = 'HIT'
      req.cachedEntryHost = cached.host
      res.status(cached.status).type(cached.contentType).send(cached.body)
      next()
      return
    }
    const originalSend = res.send.bind(res)
    res.send = (body) => {
      res.set('X-Cache', 'MISS')
      req.cacheOutcome = 'MISS'
      const contentType =
        res.get('Content-Type') || (typeof body === 'string' ? 'text/html; charset=utf-8' : 'application/octet-stream')
      store.set(key, {
        status: res.statusCode,
        contentType,
        body,
        host: req._builtHost,
        ts: Date.now(),
      })
      return originalSend(body)
    }
    next()
  }
}

function clearCache(store) {
  store.clear()
}

module.exports = { createCacheStore, cacheable, clearCache, CACHE_TTL_MS }
