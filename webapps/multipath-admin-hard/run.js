const { createApp } = require('./app')

const app = createApp({})
const PORT = app.locals.port

app.listen(PORT, () => {
  console.log(`Thornfield listening on http://localhost:${PORT}`)
})
