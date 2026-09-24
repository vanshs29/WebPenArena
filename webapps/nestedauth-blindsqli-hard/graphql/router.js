const express = require('express')
const { createHandler } = require('graphql-http')
const { NoSchemaIntrospectionCustomRule } = require('graphql')
const { buildMeridianSchema } = require('./schema')
const { requireAuth } = require('../app/auth')
const { writeEvent } = require('../app/scoring')

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    let raw = ''
    req.setEncoding('utf8')
    req.on('data', (chunk) => (raw += chunk))
    req.on('end', () => resolve(raw))
    req.on('error', reject)
  })
}

function buildGraphqlRouter(pool) {
  const router = express.Router()
  const schema = buildMeridianSchema()

  const handler = createHandler({
    schema,
    validationRules: [NoSchemaIntrospectionCustomRule],
    context: (req) => req.context,
  })

  router.all('/graphql', requireAuth, async (req, res, next) => {
    try {
      const [body, init] = await handler({
        method: req.method,
        url: req.originalUrl,
        headers: req.headers,
        body: () => readRawBody(req),
        raw: req,
        context: { member: req.member, pool },
      })

      if (typeof body === 'string' && body.includes('introspection has been disabled')) {
        await writeEvent(pool, 'recon_introspection_disabled_confirmed')
      }

      if (init.headers) {
        for (const [key, value] of Object.entries(init.headers)) {
          res.setHeader(key, value)
        }
      }
      res.status(init.status).end(body ?? undefined)
    } catch (err) {
      next(err)
    }
  })

  return router
}

module.exports = { buildGraphqlRouter }
