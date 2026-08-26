const jwt = require('jsonwebtoken')
const crypto = require('crypto')
const { writeEvent } = require('./scoring')

function issueToken(app, user) {
  const jti = crypto.randomUUID()
  const token = jwt.sign({ sub: user.id, role: user.role, jti }, app.locals.jwtSecret, {
    algorithm: 'HS256',
  })
  app.locals.db
    .prepare('INSERT INTO issued_tokens (jti, user_id, role, issued_at) VALUES (?, ?, ?, ?)')
    .run(jti, user.id, user.role, Date.now() / 1000)
  return token
}

function verifyToken(app, token) {
  let decoded
  try {
    decoded = jwt.verify(token, app.locals.jwtSecret, { algorithms: ['HS256'] })
  } catch {
    return null
  }
  const record = app.locals.db
    .prepare('SELECT role FROM issued_tokens WHERE jti = ? AND user_id = ?')
    .get(decoded.jti, decoded.sub)
  const viaForgery = !record || record.role !== decoded.role
  return { ...decoded, viaForgery }
}

function requireAuth(req, res, next) {
  const token = req.cookies && req.cookies.session
  if (!token) return res.status(401).json({ error: 'Unauthorized' })
  const payload = verifyToken(req.app, token)
  if (!payload) return res.status(401).json({ error: 'Unauthorized' })
  req.user = payload
  if (payload.viaForgery) {
    writeEvent(req.app.locals.db, 'exploit_forged_token_used', 'Forged token accepted')
  }
  next()
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' })
    if (req.user.viaForgery) {
      writeEvent(req.app.locals.db, 'exploit_admin_recognized', 'Forged admin token passed admin check')
    }
    next()
  })
}

module.exports = { issueToken, verifyToken, requireAuth, requireAdmin }
