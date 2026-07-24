import jwt from 'jsonwebtoken'

const SECRET = process.env.SESSION_SECRET || 'quickpoll-dev-secret'

export interface SessionPayload {
  sub: string
  username: string
  role: string
  looseMatch: boolean
}

export function issueToken(payload: SessionPayload): string {
  return jwt.sign(payload, SECRET, { expiresIn: '2h' })
}

export function verifyToken(token: string): SessionPayload | null {
  try {
    return jwt.verify(token, SECRET) as SessionPayload
  } catch {
    return null
  }
}
