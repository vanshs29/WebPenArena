const { createApp } = require('./app')
const { startCiSimulator } = require('./app/ciSimulator')

const app = createApp({})
const PORT = process.env.PORT || 5000

app.listen(PORT, () => {
  console.log(`Portstone listening on http://localhost:${PORT}`)
  startCiSimulator({ registryUrl: `http://127.0.0.1:${PORT}/registry/` })
})
