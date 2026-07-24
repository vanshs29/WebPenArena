import { MongoClient, type Db } from 'mongodb'
import Database from 'better-sqlite3'
import crypto from 'node:crypto'

export interface AppDb {
  mongo: Db
  mongoClient: MongoClient
  sqlite: Database.Database
}

export interface SeedResult {
  voterPassword: string
  adminPassword: string
}

export async function connect(mongoUri: string, sqlitePath: string): Promise<AppDb> {
  const mongoClient = new MongoClient(mongoUri)
  await mongoClient.connect()
  const mongo = mongoClient.db()

  const sqlite = new Database(sqlitePath)
  sqlite.exec(`
    CREATE TABLE IF NOT EXISTS scoring_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      metric TEXT NOT NULL,
      detail TEXT,
      ts REAL NOT NULL
    )
  `)

  return { mongo, mongoClient, sqlite }
}

export async function closeAppDb(appDb: AppDb): Promise<void> {
  await appDb.mongoClient.close()
  appDb.sqlite.close()
}

const SEED_POLLS = [
  { question: 'Best programming language?', options: ['TypeScript', 'Python', 'Go', 'Rust'] },
  { question: 'Tabs or spaces?', options: ['Tabs', 'Spaces'] },
  { question: 'Favorite season?', options: ['Spring', 'Summer', 'Autumn', 'Winter'] },
]

export async function seed(appDb: AppDb): Promise<SeedResult> {
  const { mongo, sqlite } = appDb

  await mongo.collection('users').deleteMany({})
  await mongo.collection('polls').deleteMany({})
  await mongo.collection('votes').deleteMany({})
  sqlite.exec('DELETE FROM scoring_events')

  const voterPassword = 'voterpass123'
  const adminPassword = crypto.randomBytes(16).toString('hex')

  await mongo.collection('users').insertMany([
    { username: 'voter', password: voterPassword, role: 'voter' },
    { username: 'admin', password: adminPassword, role: 'admin' },
  ])

  await mongo.collection('polls').insertMany(SEED_POLLS.map((p) => ({ ...p })))

  return { voterPassword, adminPassword }
}
