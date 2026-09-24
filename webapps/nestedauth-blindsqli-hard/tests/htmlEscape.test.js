const { escapeHtml } = require('../app/public/htmlEscape.js')

describe('escapeHtml', () => {
  test('leaves plain text unchanged', () => {
    expect(escapeHtml('Acme Logistics')).toBe('Acme Logistics')
  })

  test('escapes angle brackets so tags cannot be injected', () => {
    expect(escapeHtml('<img src=x onerror=alert(1)>')).toBe(
      '&lt;img src=x onerror=alert(1)&gt;'
    )
  })

  test('escapes ampersands, quotes, and apostrophes', () => {
    expect(escapeHtml(`Tom & Jerry's "co"`)).toBe(
      'Tom &amp; Jerry&#39;s &quot;co&quot;'
    )
  })

  test('neutralizes a realistic stored-XSS payload', () => {
    const payload = '<img src=x onerror=alert(document.domain)>XSSOrg'
    const escaped = escapeHtml(payload)
    expect(escaped).not.toContain('<img')
    expect(escaped).not.toContain('>')
    expect(escaped).toContain('XSSOrg')
  })

  test('coerces non-string input to a string first', () => {
    expect(escapeHtml(42)).toBe('42')
  })
})
