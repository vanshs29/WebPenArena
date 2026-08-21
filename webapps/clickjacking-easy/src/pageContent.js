const cheerio = require('cheerio')

function sanitizePageHtml(html) {
  const $ = cheerio.load(html || '', null, false)
  $('script').remove()
  return $.html()
}

function containsDeactivateIframe(html) {
  const $ = cheerio.load(html || '', null, false)
  let found = false
  $('iframe[src]').each((_, el) => {
    const src = $(el).attr('src')
    try {
      const resolved = new URL(src, 'http://billfold.internal/')
      if (resolved.pathname === '/account/deactivate') found = true
    } catch {
      // malformed src, not a match
    }
  })
  return found
}

module.exports = { sanitizePageHtml, containsDeactivateIframe }
