import path from 'node:path'
import os from 'node:os'
import fs from 'node:fs'
import crypto from 'node:crypto'
import type { FastifyInstance } from 'fastify'
import { buildApp } from '../../src/app'
import { connect, closeAppDb, seed, type AppDb, type SeedResult } from '../../src/db'

export interface TestContext {
  fastify: FastifyInstance
  appDb: AppDb
  scoreToken: string
  seedResult: SeedResult
  reseed: () => Promise<void>
  close: () => Promise<void>
}

export async function createTestContext(): Promise<TestContext> {
  const baseUri = process.env.MONGO_TEST_URI
  if (!baseUri) {
    throw new Error('MONGO_TEST_URI is not set — globalSetup did not run')
  }

  const dbName = `quickpoll_test_${crypto.randomBytes(6).toString('hex')}`
  const mongoUri = `${baseUri}${dbName}`
  const sqlitePath = path.join(os.tmpdir(), `quickpoll-scoring-${crypto.randomBytes(6).toString('hex')}.db`)

  const appDb = await connect(mongoUri, sqlitePath)
  const seedResult = await seed(appDb)
  const scoreToken = 'test-score-token'

  const fastify = await buildApp({ appDb, scoreToken })

  return {
    fastify,
    appDb,
    scoreToken,
    seedResult,
    reseed: async () => {
      await seed(appDb)
    },
    close: async () => {
      await fastify.close()
      await closeAppDb(appDb)
      try {
        fs.unlinkSync(sqlitePath)
      } catch {
        // already removed
      }
    },
  }
}
