const jwt = require('jsonwebtoken')

function issueSession(app, member) {
  return jwt.sign({ sub: String(member.id), type: 'member' }, app.locals.jwtSecret, {
    algorithm: 'HS256',
  })
}

function issuePlatformAdminSession(app, admin) {
  return jwt.sign({ sub: String(admin.id), type: 'platform_admin' }, app.locals.jwtSecret, {
    algorithm: 'HS256',
  })
}

async function requireAuth(req, res, next) {
  const token = req.cookies && req.cookies.session
  if (!token) return res.status(401).json({ error: 'authentication required' })
  let decoded
  try {
    decoded = jwt.verify(token, req.app.locals.jwtSecret, { algorithms: ['HS256'] })
  } catch {
    return res.status(401).json({ error: 'authentication required' })
  }
  if (decoded.type !== 'member') return res.status(401).json({ error: 'authentication required' })

  try {
    const pool = req.app.locals.pool
    const { rows } = await pool.query(
      'SELECT id, org_id AS "orgId", name, email, role FROM members WHERE id = $1',
      [decoded.sub]
    )
    if (rows.length === 0) return res.status(401).json({ error: 'authentication required' })
    req.member = rows[0]
    next()
  } catch (err) {
    next(err)
  }
}

async function requirePlatformAdmin(req, res, next) {
  const token = req.cookies && req.cookies.admin_session
  if (!token) return res.status(401).json({ error: 'authentication required' })
  let decoded
  try {
    decoded = jwt.verify(token, req.app.locals.jwtSecret, { algorithms: ['HS256'] })
  } catch {
    return res.status(401).json({ error: 'authentication required' })
  }
  if (decoded.type !== 'platform_admin') {
    return res.status(401).json({ error: 'authentication required' })
  }

  try {
    const pool = req.app.locals.pool
    const { rows } = await pool.query('SELECT id, email FROM platform_admins WHERE id = $1', [
      decoded.sub,
    ])
    if (rows.length === 0) return res.status(401).json({ error: 'authentication required' })
    req.platformAdmin = rows[0]
    next()
  } catch (err) {
    next(err)
  }
}

module.exports = { issueSession, issuePlatformAdminSession, requireAuth, requirePlatformAdmin }
