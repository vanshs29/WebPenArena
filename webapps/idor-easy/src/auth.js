const jwt = require('jsonwebtoken')

function issueToken(app, payload) {
  return jwt.sign(payload, app.locals.jwtSecret, { algorithm: 'HS256' })
}

function decodeToken(app, token) {
  try {
    return jwt.verify(token, app.locals.jwtSecret, { algorithms: ['HS256'] })
  } catch {
    return null
  }
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization
  let token = header && header.startsWith('Bearer ') ? header.slice(7) : null
  if (!token) token = req.cookies && req.cookies.token ? req.cookies.token : null
  if (!token) return res.status(401).json({ error: 'Unauthorized' })
  const payload = decodeToken(req.app, token)
  if (!payload) return res.status(401).json({ error: 'Unauthorized' })
  req.user = payload
  next()
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' })
    next()
  })
}

module.exports = { issueToken, decodeToken, requireAuth, requireAdmin }
