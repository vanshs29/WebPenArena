import { MongoMemoryServer } from 'mongodb-memory-server'

let mongod: MongoMemoryServer | undefined

export async function setup(): Promise<void> {
  mongod = await MongoMemoryServer.create()
  process.env.MONGO_TEST_URI = mongod.getUri()
}

export async function teardown(): Promise<void> {
  if (mongod) await mongod.stop()
}
