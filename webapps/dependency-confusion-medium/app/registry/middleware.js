function requireAccount(req, res, next) {
  const db = req.app.locals.registryDb
  const authHeader = req.headers.authorization || ''
  const match = authHeader.match(/^Bearer\s+(.+)$/i)
  if (!match) return res.status(401).json({ error: 'authentication required' })

  const account = db.prepare('SELECT username FROM accounts WHERE token = ?').get(match[1])
  if (!account) return res.status(401).json({ error: 'authentication required' })

  req.account = account
  next()
}

module.exports = { requireAccount }
