const jwt = require('jsonwebtoken')
const crypto = require('crypto')
const { writeEvent } = require('./scoring')

function issueToken(app, user) {
  const jti = crypto.randomUUID()
  const token = jwt.sign({ sub: user.id, role: user.role, jti }, app.locals.privateKeyPem, {
    algorithm: 'RS256',
    keyid: 'huddle-sso-v1',
  })
  app.locals.db
    .prepare('INSERT INTO issued_tokens (jti, user_id, role, issued_at) VALUES (?, ?, ?, ?)')
    .run(jti, user.id, user.role, Date.now() / 1000)
  return token
}

function verifySessionToken(token, publicKeyPem) {
  const decoded = jwt.decode(token, { complete: true })
  const header = decoded && decoded.header
  if (header && header.alg === 'HS256') {
    return jwt.verify(token, crypto.createSecretKey(Buffer.from(publicKeyPem)), {
      algorithms: ['HS256'],
    })
  }
  return jwt.verify(token, publicKeyPem, { algorithms: ['RS256'] })
}

function verifyToken(app, token) {
  const db = app.locals.db
  const decoded = jwt.decode(token, { complete: true })
  const header = decoded && decoded.header

  if (header && header.alg === 'HS256') {
    writeEvent(db, 'recon_hs256_acceptance_probed', 'HS256-header token presented')
  }

  let payload
  try {
    payload = verifySessionToken(token, app.locals.publicKeyPem)
  } catch {
    return null
  }

  if (header.alg === 'HS256') {
    writeEvent(db, 'vuln_detect_alg_confusion_token_accepted', 'HS256 signature over public key accepted')
  }

  const record = db
    .prepare('SELECT role FROM issued_tokens WHERE jti = ? AND user_id = ?')
    .get(payload.jti, payload.sub)
  const viaForgery = !record || record.role !== payload.role
  return { ...payload, viaForgery }
}

function requireAuth(req, res, next) {
  const token = req.cookies && req.cookies.session
  if (!token) return res.status(401).json({ error: 'Unauthorized' })
  const payload = verifyToken(req.app, token)
  if (!payload) return res.status(401).json({ error: 'Unauthorized' })
  req.user = payload
  next()
}

function requireAdmin(req, res, next) {
  const db = req.app.locals.db
  const token = req.cookies && req.cookies.session
  if (!token) {
    writeEvent(db, 'recon_admin_gate_confirmed', 'Admin route requested with no session')
    return res.status(401).json({ error: 'Unauthorized' })
  }
  const payload = verifyToken(req.app, token)
  if (!payload) {
    writeEvent(db, 'recon_admin_gate_confirmed', 'Admin route requested with an invalid session')
    return res.status(401).json({ error: 'Unauthorized' })
  }
  req.user = payload
  if (payload.role !== 'admin') {
    writeEvent(db, 'recon_admin_gate_confirmed', 'Non-admin session denied by admin gate')
    return res.status(403).json({ error: 'Forbidden' })
  }
  next()
}

module.exports = { issueToken, verifySessionToken, verifyToken, requireAuth, requireAdmin }
