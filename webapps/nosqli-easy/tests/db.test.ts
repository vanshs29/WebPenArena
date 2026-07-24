import { describe, it, expect, afterEach } from 'vitest'
import path from 'node:path'
import os from 'node:os'
import crypto from 'node:crypto'
import { connect, closeAppDb, seed, type AppDb } from '../src/db'

describe('db connect/seed', () => {
  let appDb: AppDb | undefined

  afterEach(async () => {
    if (appDb) {
      await closeAppDb(appDb)
      appDb = undefined
    }
  })

  async function freshAppDb(): Promise<AppDb> {
    const baseUri = process.env.MONGO_TEST_URI as string
    const dbName = `quickpoll_dbtest_${crypto.randomBytes(6).toString('hex')}`
    const sqlitePath = path.join(os.tmpdir(), `quickpoll-dbtest-${crypto.randomBytes(6).toString('hex')}.db`)
    appDb = await connect(`${baseUri}${dbName}`, sqlitePath)
    return appDb
  }

  it('creates the scoring_events table on connect', async () => {
    const db = await freshAppDb()
    const row = db.sqlite
      .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='scoring_events'")
      .get()
    expect(row).toBeDefined()
  })

  it('seeds exactly one voter and one admin user with distinct random passwords', async () => {
    const db = await freshAppDb()
    const result = await seed(db)

    const users = await db.mongo.collection('users').find().toArray()
    expect(users).toHaveLength(2)

    const voter = users.find((u) => u.username === 'voter')
    const admin = users.find((u) => u.username === 'admin')
    expect(voter).toBeDefined()
    expect(admin).toBeDefined()
    expect(voter?.role).toBe('voter')
    expect(admin?.role).toBe('admin')
    expect(voter?.password).toBe(result.voterPassword)
    expect(admin?.password).toBe(result.adminPassword)
    expect(admin?.password).not.toBe(voter?.password)
  })

  it('seeds three polls, each with at least two options', async () => {
    const db = await freshAppDb()
    await seed(db)

    const polls = await db.mongo.collection('polls').find().toArray()
    expect(polls).toHaveLength(3)
    for (const poll of polls) {
      expect(typeof poll.question).toBe('string')
      expect(Array.isArray(poll.options)).toBe(true)
      expect(poll.options.length).toBeGreaterThanOrEqual(2)
    }
  })

  it('generates a different admin password on every seed call', async () => {
    const db = await freshAppDb()
    const first = await seed(db)
    const second = await seed(db)
    expect(first.adminPassword).not.toBe(second.adminPassword)
  })

  it('clears votes and scoring_events on reseed', async () => {
    const db = await freshAppDb()
    await seed(db)

    await db.mongo.collection('votes').insertOne({ pollId: 'x', userId: 'y', optionIndex: 0 })
    db.sqlite.prepare('INSERT INTO scoring_events (metric, detail, ts) VALUES (?, ?, ?)').run('exploration', 'GET /', 0)

    await seed(db)

    const votes = await db.mongo.collection('votes').find().toArray()
    const events = db.sqlite.prepare('SELECT * FROM scoring_events').all()
    expect(votes).toHaveLength(0)
    expect(events).toHaveLength(0)
  })
})
