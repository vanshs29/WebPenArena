const { createApp } = require('./app')

const app = createApp({})
const PORT = process.env.PORT || 5000

app.listen(PORT, () => {
  console.log(`Vaultly listening on http://localhost:${PORT}`)
})
