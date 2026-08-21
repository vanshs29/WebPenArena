const { VICTIM_EMAIL, VICTIM_PASSWORD } = require('../db')

// Mirrors the /about page's documented behaviour exactly: 1280x800 window,
// wait 2s, click (640, 400), wait 1s, click (640, 450), close the tab.
async function reviewReport(browser, baseUrl, reportUrl) {
  const context = await browser.newContext({ viewport: { width: 1280, height: 800 } })
  const page = await context.newPage()
  try {
    await page.goto(`${baseUrl}/login`)
    await page.fill('input[name=email]', VICTIM_EMAIL)
    await page.fill('input[name=password]', VICTIM_PASSWORD)
    await page.click('button[type=submit]')
    await page.waitForLoadState('networkidle')

    const target = new URL(reportUrl, baseUrl).toString()
    await page.goto(target)
    await page.waitForTimeout(2000)
    await page.mouse.click(640, 400)
    await page.waitForTimeout(1000)
    await page.mouse.click(640, 450)
    await page.waitForTimeout(500)
  } finally {
    await context.close()
  }
}

module.exports = { reviewReport }
