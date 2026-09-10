const path = require('path')
const { createApp } = require('./app')

const app = createApp({ dataDir: path.join(__dirname, 'data') })
const PORT = process.env.PORT || 5000

app.listen(PORT, () => {
  console.log(`Huddle listening on http://localhost:${PORT}`)
})
