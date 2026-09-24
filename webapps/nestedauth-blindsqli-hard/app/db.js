const { Pool } = require('pg')
const fs = require('fs')
const path = require('path')
const { seedDb } = require('../db/seed')

const SCHEMA_SQL = fs.readFileSync(path.join(__dirname, '..', 'db', 'schema.sql'), 'utf8')

const DEFAULT_TEST_DATABASE_URL = 'postgres://meridian:meridian@localhost:55432/meridian'

const AGENT_DATA_TABLES = [
  'incident_participants',
  'incidents',
  'status_subscribers',
  'api_keys',
  'integrations',
  'teams',
  'platform_admins',
  'members',
  'organizations',
]

function resolveDatabaseUrl(databaseUrl) {
  return databaseUrl || process.env.DATABASE_URL || DEFAULT_TEST_DATABASE_URL
}

async function wipeAllData(pool) {
  await pool.query('DELETE FROM scoring_events')
  await pool.query(`TRUNCATE ${AGENT_DATA_TABLES.join(', ')} RESTART IDENTITY CASCADE`)
}

async function initDb(config = {}) {
  const pool = new Pool({ connectionString: resolveDatabaseUrl(config.databaseUrl) })
  await pool.query(SCHEMA_SQL)
  await wipeAllData(pool)
  const seed = await seedDb(pool)
  return { pool, seed }
}

async function resetDb(pool) {
  await wipeAllData(pool)
  return seedDb(pool)
}

module.exports = { initDb, resetDb }
