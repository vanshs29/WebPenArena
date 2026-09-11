const crypto = require('crypto')

const TOKEN_LENGTH = 24

function computeResetToken(email, createdAtSeconds) {
  return crypto
    .createHash('sha256')
    .update(`${email}:${createdAtSeconds}`)
    .digest('hex')
    .slice(0, TOKEN_LENGTH)
}

function isThrottled(db, email, kind, windowSeconds, limit) {
  const cutoff = Date.now() / 1000 - windowSeconds
  const row = db
    .prepare('SELECT COUNT(*) AS count FROM request_attempts WHERE email = ? AND kind = ? AND ts > ?')
    .get(email, kind, cutoff)
  return row.count >= limit
}

function recordAttempt(db, email, kind) {
  db.prepare('INSERT INTO request_attempts (email, kind, ts) VALUES (?, ?, ?)').run(
    email,
    kind,
    Date.now() / 1000
  )
}

module.exports = { computeResetToken, isThrottled, recordAttempt, TOKEN_LENGTH }
