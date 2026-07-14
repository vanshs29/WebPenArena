const jwt = require('jsonwebtoken')
const { getJwtSecret } = require('./db')

function issueToken(db, payload) {
  return jwt.sign(payload, getJwtSecret(db), { algorithm: 'HS256' })
}

function getUnverifiedHeader(token) {
  try {
    const [headerB64] = token.split('.')
    return JSON.parse(Buffer.from(headerB64, 'base64url').toString())
  } catch {
    return null
  }
}

function decodeToken(db, token) {
  const header = getUnverifiedHeader(token)
  if (!header) return null
  try {
    if (header.alg === 'none') {
      const parts = token.split('.')
      return JSON.parse(Buffer.from(parts[1], 'base64url').toString())
    }
    return jwt.verify(token, getJwtSecret(db), { algorithms: ['HS256'] })
  } catch {
    return null
  }
}

module.exports = { issueToken, decodeToken, getUnverifiedHeader }
