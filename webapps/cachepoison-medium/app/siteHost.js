function resolveSiteHost(req) {
  return req.headers['x-forwarded-host'] || req.app.locals.siteHost
}

function buildCanonicalLink(articleId, host) {
  return `https://${host}/articles/${articleId}`
}

function buildWidgetScriptUrl(host) {
  return `https://${host}/js/widget.js`
}

module.exports = { resolveSiteHost, buildCanonicalLink, buildWidgetScriptUrl }
