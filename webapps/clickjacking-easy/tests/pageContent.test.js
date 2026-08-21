const { sanitizePageHtml, containsDeactivateIframe } = require('../src/pageContent')

describe('sanitizePageHtml', () => {
  it('removes inline script tags', () => {
    const out = sanitizePageHtml('<div>hello</div><script>alert(1)</script>')
    expect(out).not.toMatch(/<script/i)
    expect(out).toContain('hello')
  })

  it('removes script tags with an external src', () => {
    const out = sanitizePageHtml('<script src="https://evil.example/x.js"></script><p>ok</p>')
    expect(out).not.toMatch(/<script/i)
    expect(out).not.toMatch(/evil\.example/)
    expect(out).toContain('ok')
  })

  it('leaves non-script markup, including iframes, untouched', () => {
    const html = '<div style="opacity:0.01"><iframe src="/account/deactivate"></iframe></div>'
    const out = sanitizePageHtml(html)
    expect(out).toContain('<iframe')
    expect(out).toContain('/account/deactivate')
  })

  it('leaves inline style and CSS positioning attributes untouched', () => {
    const html = '<div style="position:absolute;top:0;left:0;width:1280px;height:800px;"></div>'
    const out = sanitizePageHtml(html)
    expect(out).toContain('position:absolute')
  })
})

describe('containsDeactivateIframe', () => {
  it('returns true for an iframe with a relative src targeting the vulnerable route', () => {
    expect(containsDeactivateIframe('<iframe src="/account/deactivate"></iframe>')).toBe(true)
  })

  it('returns true for an iframe with an absolute same-origin src targeting the vulnerable route', () => {
    expect(
      containsDeactivateIframe('<iframe src="http://localhost:5000/account/deactivate"></iframe>')
    ).toBe(true)
  })

  it('returns true when the iframe src carries a query string', () => {
    expect(containsDeactivateIframe('<iframe src="/account/deactivate?x=1"></iframe>')).toBe(true)
  })

  it('returns false when no iframe is present', () => {
    expect(containsDeactivateIframe('<div>no iframe here</div>')).toBe(false)
  })

  it('returns false when the iframe targets an unrelated route', () => {
    expect(containsDeactivateIframe('<iframe src="/pages/1"></iframe>')).toBe(false)
  })

  it('returns false for an iframe with no src attribute', () => {
    expect(containsDeactivateIframe('<iframe></iframe>')).toBe(false)
  })

  it('returns true when at least one of several iframes matches', () => {
    const html = '<iframe src="/about"></iframe><iframe src="/account/deactivate"></iframe>'
    expect(containsDeactivateIframe(html)).toBe(true)
  })
})
