const EMBEDDABLE_PATH_PREFIXES = ['/pages/']

function frameProtection(req, res, next) {
  const allowed = EMBEDDABLE_PATH_PREFIXES.some((p) => req.path.startsWith(p))
  if (!allowed) {
    res.setHeader('X-Frame-Options', 'DENY')
    res.setHeader('Content-Security-Policy', "frame-ancestors 'none'")
  }
  next()
}

module.exports = { frameProtection }
