const jwt = require('jsonwebtoken')

function issueSession(app, user) {
  return jwt.sign({ sub: String(user.id) }, app.locals.jwtSecret, { algorithm: 'HS256' })
}

function issuePlatformAdminSession(app) {
  return jwt.sign({ platformOverride: true }, app.locals.jwtSecret, { algorithm: 'HS256' })
}

function loadUserWithWorkspace(db, userId) {
  return db
    .prepare(
      `SELECT users.id, users.email, users.role, users.workspace_id AS workspaceId,
              workspaces.name AS workspaceName, workspaces.is_seed AS workspaceIsSeed
       FROM users JOIN workspaces ON workspaces.id = users.workspace_id
       WHERE users.id = ?`
    )
    .get(userId)
}

function decodeSession(req) {
  const token = req.cookies && req.cookies.session
  if (!token) return null
  try {
    return jwt.verify(token, req.app.locals.jwtSecret, { algorithms: ['HS256'] })
  } catch {
    return null
  }
}

function requireAuth(req, res, next) {
  const decoded = decodeSession(req)
  if (!decoded || !decoded.sub) return res.status(401).json({ error: 'Unauthorized' })
  const user = loadUserWithWorkspace(req.app.locals.db, decoded.sub)
  if (!user) return res.status(401).json({ error: 'Unauthorized' })
  req.user = user
  next()
}

function requireWorkspaceAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' })
  next()
}

function requirePlatformAccess(req, res, next) {
  const decoded = decodeSession(req)
  if (!decoded) return res.status(401).json({ error: 'Unauthorized' })
  if (decoded.platformOverride === true) {
    req.platformOverride = true
    return next()
  }
  if (decoded.sub) {
    const user = loadUserWithWorkspace(req.app.locals.db, decoded.sub)
    if (user && user.role === 'admin' && user.workspaceIsSeed === 1) {
      req.user = user
      return next()
    }
  }
  return res.status(403).json({ error: 'Forbidden' })
}

module.exports = {
  issueSession,
  issuePlatformAdminSession,
  requireAuth,
  requireWorkspaceAdmin,
  requirePlatformAccess,
  loadUserWithWorkspace,
}
