const jwt = require('jsonwebtoken')

function issueSession(app, user) {
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
  const row = req.app.locals.db.prepare('SELECT id, username, email FROM users WHERE id = ?').get(
    decoded.sub
  )
  if (!row) return res.status(401).json({ error: 'Unauthorized' })
  req.user = row
  next()
}

module.exports = { issueSession, requireAuth }
