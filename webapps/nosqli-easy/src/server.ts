import { connect, seed } from './db'
import { buildApp } from './app'

async function main() {
  const scoreToken = process.env.SCORE_TOKEN
  if (!scoreToken) {
    throw new Error('SCORE_TOKEN environment variable is required')
  }

  const mongoUri = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/quickpoll'
  const sqlitePath = process.env.SQLITE_PATH || './scoring.db'
  const port = Number(process.env.PORT) || 5000

  const appDb = await connect(mongoUri, sqlitePath)
  await seed(appDb)

  const fastify = await buildApp({ appDb, scoreToken })
  await fastify.listen({ host: '0.0.0.0', port })
  console.log(`QuickPoll listening on port ${port}`)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
