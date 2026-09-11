const crypto = require('crypto')
const fs = require('fs')
const path = require('path')

function parseJwt(token) {
  const [headerB64, payloadB64, sigB64] = token.split('.')
  const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString())
  const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString())
  return { header, payload, headerB64, payloadB64, sigB64 }
}

function verifyX5cToken(token) {
  let parsed
  try {
    parsed = parseJwt(token)
  } catch {
    return null
  }
  const { header, payload, headerB64, payloadB64, sigB64 } = parsed
  if (header.alg !== 'RS256' || !Array.isArray(header.x5c) || !header.x5c[0]) return null

  let publicKey
  try {
    const certDer = Buffer.from(header.x5c[0], 'base64')
    publicKey = new crypto.X509Certificate(certDer).publicKey
  } catch {
    return null
  }

  const signingInput = `${headerB64}.${payloadB64}`
  const signature = Buffer.from(sigB64, 'base64url')
  const verified = crypto.verify('RSA-SHA256', Buffer.from(signingInput), publicKey, signature)
  return verified ? payload : null
}

function verifyKidToken(token, keysDir) {
  let parsed
  try {
    parsed = parseJwt(token)
  } catch {
    return null
  }
  const { header, payload, headerB64, payloadB64, sigB64 } = parsed
  if (header.alg !== 'HS256' || typeof header.kid !== 'string') return null

  let secret
  try {
    secret = fs.readFileSync(path.join(keysDir, header.kid), 'utf8').trim()
  } catch {
    return null
  }

  const signingInput = `${headerB64}.${payloadB64}`
  const expected = crypto.createHmac('sha256', secret).update(signingInput).digest('base64url')
  return expected === sigB64 ? payload : null
}

module.exports = { parseJwt, verifyX5cToken, verifyKidToken }
