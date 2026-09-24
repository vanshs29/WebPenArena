const Database = require('better-sqlite3')
const fs = require('fs')
const path = require('path')
const { seedDb } = require('../db/seed')

const SCHEMA_SQL = fs.readFileSync(path.join(__dirname, '..', 'db', 'schema.sql'), 'utf8')

const AGENT_DATA_TABLES = ['saved_views', 'tickets', 'users', 'workspaces']

function wipeAllData(db) {
  db.exec('DELETE FROM scoring_events')
  db.exec('DELETE FROM telemetry_reports')
  for (const table of AGENT_DATA_TABLES) {
    db.exec(`DELETE FROM ${table}`)
    db.exec(`DELETE FROM sqlite_sequence WHERE name = '${table}'`)
  }
}

function initDb(dbPath) {
  const db = new Database(dbPath)
  db.pragma('journal_mode = WAL')
  db.exec(SCHEMA_SQL)
  const seed = seedDb(db)
  return { db, seed }
}

function resetDb(db) {
  wipeAllData(db)
  return seedDb(db)
}

module.exports = { initDb, resetDb }
