const { chromium } = require('playwright')

// PLAYWRIGHT_CHROMIUM_PATH lets a local dev/test environment point at a
// pre-installed browser binary if the default Playwright browser resolution
// doesn't apply (e.g. a cached build under a non-standard revision). The
// Docker image ships a matching bundled browser, so this is unset in
// production and default resolution is used.
function launchBrowser() {
  const options = {}
  if (process.env.PLAYWRIGHT_CHROMIUM_PATH) {
    options.executablePath = process.env.PLAYWRIGHT_CHROMIUM_PATH
  }
  return chromium.launch(options)
}

module.exports = { launchBrowser }
