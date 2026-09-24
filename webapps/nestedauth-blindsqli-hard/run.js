const { createApp } = require('./app')

const PORT = process.env.PORT || 5000

createApp()
  .then((app) => {
    app.listen(PORT, () => {
      console.log(`Meridian listening on port ${PORT}`)
    })
  })
  .catch((err) => {
    console.error('Failed to start Meridian:', err)
    process.exit(1)
  })
