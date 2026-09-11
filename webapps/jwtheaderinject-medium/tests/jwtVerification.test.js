const crypto = require('crypto')
const path = require('path')
const { parseJwt, verifyX5cToken, verifyKidToken } = require('../app/jwtVerification')
const { generateSelfSignedCert, signX5cToken, signKidToken, TRAVERSAL_KID } = require('./helpers')

const FIXTURE_KEYS_DIR = path.join(__dirname, 'fixtures', 'keys')

describe('parseJwt', () => {
  test('decodes a well-formed token\'s header and payload', () => {
    const header = { alg: 'HS256', typ: 'JWT' }
    const payload = { sub: '1' }
    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url')
    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url')
    const token = `${headerB64}.${payloadB64}.sig`
    const parsed = parseJwt(token)
    expect(parsed.header).toEqual(header)
    expect(parsed.payload).toEqual(payload)
  })

  test('throws on a token with invalid base64url segments', () => {
    expect(() => parseJwt('not-a-jwt')).toThrow()
  })
})

describe('verifyX5cToken', () => {
  test('returns null when alg is not RS256', () => {
    const header = { alg: 'HS256', x5c: ['abc'] }
    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url')
    const payloadB64 = Buffer.from(JSON.stringify({ partner_id: 'x' })).toString('base64url')
    expect(verifyX5cToken(`${headerB64}.${payloadB64}.sig`)).toBeNull()
  })

  test('returns null when x5c is missing', () => {
    const header = { alg: 'RS256' }
    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url')
    const payloadB64 = Buffer.from(JSON.stringify({ partner_id: 'x' })).toString('base64url')
    expect(verifyX5cToken(`${headerB64}.${payloadB64}.sig`)).toBeNull()
  })

  test('returns null when x5c is present but empty', () => {
    const header = { alg: 'RS256', x5c: [] }
    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url')
    const payloadB64 = Buffer.from(JSON.stringify({ partner_id: 'x' })).toString('base64url')
    expect(verifyX5cToken(`${headerB64}.${payloadB64}.sig`)).toBeNull()
  })

  test('returns the payload for a correctly self-signed token', async () => {
    const cert = await generateSelfSignedCert()
    const token = signX5cToken({ partner_id: 'acme-enterprise' }, cert)
    expect(verifyX5cToken(token)).toEqual({ partner_id: 'acme-enterprise' })
  })

  test('returns null when the payload was tampered with after signing', async () => {
    const cert = await generateSelfSignedCert()
    const token = signX5cToken({ partner_id: 'acme-enterprise' }, cert)
    const [headerB64, , sigB64] = token.split('.')
    const tamperedPayloadB64 = Buffer.from(JSON.stringify({ partner_id: 'default-tier' })).toString(
      'base64url'
    )
    const tampered = `${headerB64}.${tamperedPayloadB64}.${sigB64}`
    expect(verifyX5cToken(tampered)).toBeNull()
  })

  test('does not throw and returns null for a non-base64 x5c value', () => {
    const header = { alg: 'RS256', x5c: ['%%%not-base64%%%'] }
    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url')
    const payloadB64 = Buffer.from(JSON.stringify({ partner_id: 'x' })).toString('base64url')
    expect(() => verifyX5cToken(`${headerB64}.${payloadB64}.sig`)).not.toThrow()
    expect(verifyX5cToken(`${headerB64}.${payloadB64}.sig`)).toBeNull()
  })
})

describe('verifyKidToken', () => {
  test('returns null when alg is not HS256', () => {
    const header = { alg: 'RS256', kid: 'default-tier' }
    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url')
    const payloadB64 = Buffer.from(JSON.stringify({ partner_id: 'x' })).toString('base64url')
    expect(verifyKidToken(`${headerB64}.${payloadB64}.sig`, FIXTURE_KEYS_DIR)).toBeNull()
  })

  test('returns null when kid is not a string', () => {
    const header = { alg: 'HS256', kid: 12345 }
    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url')
    const payloadB64 = Buffer.from(JSON.stringify({ partner_id: 'x' })).toString('base64url')
    expect(verifyKidToken(`${headerB64}.${payloadB64}.sig`, FIXTURE_KEYS_DIR)).toBeNull()
  })

  test('validates correctly against a real registered key (normal, non-traversal usage)', () => {
    const secret = require('fs').readFileSync(path.join(FIXTURE_KEYS_DIR, 'default-tier'), 'utf8').trim()
    const token = signKidToken({ partner_id: 'default-tier' }, 'default-tier', secret)
    expect(verifyKidToken(token, FIXTURE_KEYS_DIR)).toEqual({ partner_id: 'default-tier' })
  })

  test('rejects a token signed with the wrong secret for a real kid', () => {
    const token = signKidToken({ partner_id: 'default-tier' }, 'default-tier', 'totally-wrong-secret')
    expect(verifyKidToken(token, FIXTURE_KEYS_DIR)).toBeNull()
  })

  test('validates a traversal kid signed with the resulting empty secret', () => {
    const token = signKidToken({ partner_id: 'acme-enterprise', order_id: 1 }, TRAVERSAL_KID, '')
    expect(verifyKidToken(token, FIXTURE_KEYS_DIR)).toEqual({ partner_id: 'acme-enterprise', order_id: 1 })
  })

  test('does not throw and returns null for a kid naming a nonexistent file', () => {
    const token = signKidToken({ partner_id: 'x' }, 'no-such-key', '')
    expect(() => verifyKidToken(token, FIXTURE_KEYS_DIR)).not.toThrow()
    expect(verifyKidToken(token, FIXTURE_KEYS_DIR)).toBeNull()
  })
})
