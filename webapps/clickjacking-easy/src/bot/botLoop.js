const { reviewReport } = require('./reviewBot')

async function processPendingReports(browser, db, baseUrl) {
  const pending = db.prepare('SELECT * FROM reports WHERE reviewed = 0').all()
  for (const report of pending) {
    await reviewReport(browser, baseUrl, report.url)
    db.prepare('UPDATE reports SET reviewed = 1 WHERE id = ?').run(report.id)
  }
}

function createBotLoop(browser, db, baseUrl, intervalMs = 3000) {
  let timer = null
  return {
    start() {
      timer = setInterval(() => {
        processPendingReports(browser, db, baseUrl).catch((err) => {
          console.error('review bot cycle failed:', err)
        })
      }, intervalMs)
    },
    stop() {
      if (timer) clearInterval(timer)
    },
  }
}

module.exports = { processPendingReports, createBotLoop }
