const express = require('express')
const cookieParser = require('cookie-parser')
const path = require('path')
const crypto = require('crypto')
const { writeEvent } = require('./scoring')

function createApp(config = {}) {
  const app = express()

  const prisma = config.prisma
  if (!prisma) throw new Error('createApp requires a prisma client')

  app.locals.prisma = prisma
  app.locals.scoreToken = config.scoreToken || process.env.SCORE_TOKEN || ''
  app.locals.jwtSecret = crypto.randomBytes(32).toString('hex')

  app.set('view engine', 'ejs')
  app.set('views', path.join(__dirname, 'views'))

  app.use(express.json())
  app.use(express.urlencoded({ extended: true }))
  app.use(cookieParser())

  const { router } = require('./routes')
  app.use(router)

  app.use(async (err, req, res, next) => {
    if (err && err.name === 'PrismaClientValidationError' && req.path === '/reset-password/confirm') {
      try {
        await writeEvent(prisma, 'recon_orm_error_leaked')
      } catch {}
    }
    res.status(500).json({ error: `${err.name}: ${err.message}` })
  })

  return app
}

module.exports = { createApp }
