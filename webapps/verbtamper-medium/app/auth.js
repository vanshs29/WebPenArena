const jwt = require('jsonwebtoken')

function issueSession(app, user) {
  return jwt.sign({ sub: String(user.id) }, app.locals.jwtSecret, { algorithm: 'HS256' })
}

function requireAuth(req, res, next) {
  const token = req.cookies && req.cookies.session
  if (!token) return res.status(401).json({ error: 'authentication required' })
  let decoded
  try {
    decoded = jwt.verify(token, req.app.locals.jwtSecret, { algorithms: ['HS256'] })
  } catch {
    return res.status(401).json({ error: 'authentication required' })
  }
  const row = req.app.locals.db
    .prepare('SELECT id, username, email, role FROM users WHERE id = ?')
    .get(decoded.sub)
  if (!row) return res.status(401).json({ error: 'authentication required' })
  req.user = row
  next()
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'admin only' })
  next()
}

module.exports = { issueSession, requireAuth, requireAdmin }
