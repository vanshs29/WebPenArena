const jwt = require('jsonwebtoken')

function issueToken(app, user) {
  return jwt.sign({ sub: String(user.id) }, app.locals.jwtSecret, { algorithm: 'HS256' })
}

function requireAuth(req, res, next) {
  const token = req.cookies && req.cookies.session
  if (!token) return res.status(401).json({ error: 'Unauthorized' })
  let decoded
  try {
    decoded = jwt.verify(token, req.app.locals.jwtSecret, { algorithms: ['HS256'] })
  } catch {
    return res.status(401).json({ error: 'Unauthorized' })
  }
  const row = req.app.locals.db
    .prepare('SELECT id, email, role FROM users WHERE id = ?')
    .get(decoded.sub)
  if (!row) return res.status(401).json({ error: 'Unauthorized' })
  req.user = { id: row.id, email: row.email, role: row.role }
  next()
}

function requireOwnerAccess(req, res, next) {
  if (req.user.role === 'owner' || req.user.isAdmin) return next()
  res.status(403).json({ error: 'Forbidden' })
}

module.exports = { issueToken, requireAuth, requireOwnerAccess }
