const { writeEvent } = require('./scoring')

function trackExploration(detail) {
  return (req, res, next) => {
    writeEvent(req.app.locals.db, 'exploration', detail)
    next()
  }
}

module.exports = { trackExploration }
