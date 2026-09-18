const { createApp } = require('./app')
const { startArchiveSimulator, DEFAULT_ARCHIVE_INTERVAL_MS } = require('./app/archiveSimulator')

const app = createApp({})
const PORT = process.env.PORT || 5000
const ARCHIVE_INTERVAL_MS = Number(process.env.ARCHIVE_INTERVAL_MS || DEFAULT_ARCHIVE_INTERVAL_MS)

app.listen(PORT, () => {
  console.log(`Ashwell listening on http://localhost:${PORT}`)
  startArchiveSimulator(app, ARCHIVE_INTERVAL_MS)
})
