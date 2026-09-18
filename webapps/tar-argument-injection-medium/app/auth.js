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
  const row = req.app.locals.db.prepare('SELECT id, email, username FROM users WHERE id = ?').get(decoded.sub)
  if (!row) return res.status(401).json({ error: 'Unauthorized' })
  req.user = row
  next()
}

function requireOwnCase(req, res, next) {
  const db = req.app.locals.db
  const caseRow = db.prepare('SELECT * FROM cases WHERE id = ?').get(req.params.id)
  if (!caseRow) return res.status(404).json({ error: 'Not found' })
  if (caseRow.user_id !== req.user.id) return res.status(403).json({ error: 'Forbidden' })
  req.case = caseRow
  next()
}

module.exports = { issueSession, requireAuth, requireOwnCase }
