const crypto = require('crypto')
const jwt = require('jsonwebtoken')
const { asyncHandler } = require('./asyncHandler')

function generateResetToken() {
  return crypto.randomBytes(24).toString('hex')
}

function issueSession(app, user) {
  return jwt.sign({ sub: String(user.id) }, app.locals.jwtSecret, { algorithm: 'HS256' })
}

const requireAuth = asyncHandler(async (req, res, next) => {
  const token = req.cookies && req.cookies.session
  if (!token) return res.status(401).json({ error: 'Unauthorized' })

  let decoded
  try {
    decoded = jwt.verify(token, req.app.locals.jwtSecret, { algorithms: ['HS256'] })
  } catch {
    return res.status(401).json({ error: 'Unauthorized' })
  }

  const user = await req.app.locals.prisma.user.findUnique({ where: { id: Number(decoded.sub) } })
  if (!user) return res.status(401).json({ error: 'Unauthorized' })

  req.user = user
  next()
})

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' })
  next()
}

module.exports = { generateResetToken, issueSession, requireAuth, requireAdmin }
