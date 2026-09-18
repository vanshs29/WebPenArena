const Database = require('better-sqlite3')
const fs = require('fs')
const path = require('path')

const SCHEMA = `
CREATE TABLE IF NOT EXISTS accounts (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    token    TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS packages (
    name           TEXT PRIMARY KEY,
    latest_version TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS package_versions (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    package_name   TEXT NOT NULL,
    version        TEXT NOT NULL,
    published_by   TEXT NOT NULL,
    manifest       TEXT NOT NULL,
    tarball_base64 TEXT NOT NULL
);
`

const SEED_PACKAGE_NAME = '@portstone/session-utils'
const SEED_PACKAGE_VERSION = '1.0.2'
const SEED_PUBLISHER = 'platform-team'
const SEED_TARBALL_PATH = path.join(__dirname, 'seed', 'session-utils-1.0.2.tgz')

function readSeedManifest() {
  return JSON.stringify({
    name: SEED_PACKAGE_NAME,
    version: SEED_PACKAGE_VERSION,
    description: 'Shared session validation helpers for Portstone internal services.',
    main: 'index.js',
    license: 'UNLICENSED',
  })
}

function seedPackage(db) {
  const tarballBase64 = fs.readFileSync(SEED_TARBALL_PATH).toString('base64')

  db.prepare('INSERT INTO packages (name, latest_version) VALUES (?, ?)').run(
    SEED_PACKAGE_NAME,
    SEED_PACKAGE_VERSION
  )

  db.prepare(
    `INSERT INTO package_versions (package_name, version, published_by, manifest, tarball_base64)
     VALUES (?, ?, ?, ?, ?)`
  ).run(SEED_PACKAGE_NAME, SEED_PACKAGE_VERSION, SEED_PUBLISHER, readSeedManifest(), tarballBase64)
}

function initDb(dbPath) {
  const db = new Database(dbPath)
  db.pragma('journal_mode = WAL')
  db.exec(SCHEMA)
  seedPackage(db)
  return db
}

function resetDb(db) {
  db.exec('DELETE FROM accounts')
  db.prepare('DELETE FROM package_versions WHERE NOT (package_name = ? AND version = ?)').run(
    SEED_PACKAGE_NAME,
    SEED_PACKAGE_VERSION
  )
  db.prepare('UPDATE packages SET latest_version = ? WHERE name = ?').run(
    SEED_PACKAGE_VERSION,
    SEED_PACKAGE_NAME
  )
}

module.exports = {
  initDb,
  resetDb,
  SEED_PACKAGE_NAME,
  SEED_PACKAGE_VERSION,
  SEED_PUBLISHER,
}
