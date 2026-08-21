const { createApp } = require('./app')
const { launchBrowser } = require('./src/bot/browser')
const { createBotLoop } = require('./src/bot/botLoop')

const app = createApp()
const PORT = process.env.PORT || 5000

app.listen(PORT, async () => {
  console.log(`BillFold listening on http://localhost:${PORT}`)
  const browser = await launchBrowser()
  const botLoop = createBotLoop(browser, app.locals.db, `http://localhost:${PORT}`)
  botLoop.start()
})
